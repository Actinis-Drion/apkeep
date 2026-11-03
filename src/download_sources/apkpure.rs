use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::path::Path;
use std::rc::Rc;

use futures_util::StreamExt;
use indicatif::MultiProgress;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Url, Response};
use serde_json::json;
use tokio_dl_stream_to_disk::{AsyncDownload, error::ErrorKind as TDSTDErrorKind};
use tokio::time::{sleep, Duration as TokioDuration};

use crate::util::{OutputFormat, progress_bar::progress_wrapper};

fn http_headers(options: &HashMap<&str, &str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-cv", HeaderValue::from_static("3172501"));
    headers.insert("x-sv", sdk_header(options));
    let arch = match options.get("arch"){
        Some(arch) => {
            arch.split(";").collect::<Vec<_>>().join(",")
        },
        None => "arm64-v8a,armeabi-v7a,armeabi,x86,x86_64".to_string()
    };
    match HeaderValue::from_str(&arch) {
        Ok(abis_header) => {
            headers.insert(
                "x-abis",
                abis_header
            );
        },
        Err(_) => {
            println!("Invalid options specified, excluding device arch specification.");
        }
    }
    headers.insert("x-gp", HeaderValue::from_static("1"));
    headers
}

/// The `x-sv` header: the device SDK level APKPure filters its variants by.
/// `sdk=<level>` overrides the historical default of 29, so a caller can ask
/// for the builds a current device would get.
fn sdk_header(options: &HashMap<&str, &str>) -> HeaderValue {
    match options.get("sdk") {
        Some(sdk) if !sdk.is_empty() && sdk.len() <= 3 && sdk.bytes().all(|b| b.is_ascii_digit()) => {
            HeaderValue::from_str(sdk).unwrap()
        },
        Some(_) => {
            println!("Invalid sdk option specified, using the default SDK level 29.");
            HeaderValue::from_static("29")
        },
        None => HeaderValue::from_static("29"),
    }
}

/// True when `all_variants=true` asks for every descriptor of an exact
/// version instead of only the first one APKPure lists.
fn all_variants(options: &HashMap<&str, &str>) -> bool {
    matches!(options.get("all_variants"), Some(val) if *val == "1" || val.to_lowercase() == "true")
}

/// The (kind, URL) of each download descriptor `re` finds in `body`, in the
/// order APKPure lists them, without repeats; only the first unless `all`.
fn download_descriptors(re: &Regex, body: &str, all: bool) -> Vec<(String, String)> {
    let mut seen = HashSet::new();
    let mut descriptors = Vec::new();
    for caps in re.captures_iter(body) {
        let (Some(kind), Some(url)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if seen.insert(url.as_str().to_string()) {
            descriptors.push((kind.as_str().to_string(), url.as_str().to_string()));
            if !all {
                break;
            }
        }
    }
    descriptors
}

/// The file name for descriptor `index` of `count`: numbered only when there
/// are several, so a single download keeps its historical name.
fn descriptor_file_name(app_string: &str, kind: &str, index: usize, count: usize) -> String {
    let extension = match kind {
        "XAPKJ" => "xapk",
        _ => "apk",
    };
    if count > 1 {
        format!("{}.variant{}.{}", app_string, index + 1, extension)
    } else {
        format!("{}.{}", app_string, extension)
    }
}

pub async fn download_apps(
    apps: Vec<(String, Option<String>)>,
    parallel: usize,
    sleep_duration: u64,
    outpath: &Path,
    options: HashMap<&str, &str>,
) {
    match options.get("acknowledge_dangers") {
        Some(val) if *val == "1" || val.to_lowercase() == "true" => {},
        _ => {
            eprintln!("The dangers of using this download source must be explicitly acknowledged: https://github.com/EFForg/apkeep/blob/master/USAGE-apkpure.md");
            std::process::exit(1);
        }
    }

    let mp = Rc::new(MultiProgress::new());
    let http_client = Rc::new(reqwest::Client::new());
    let app_arch = options.get("arch").cloned();
    let all_variants = all_variants(&options);
    let headers = http_headers(&options);
    let re = Rc::new(Regex::new(crate::consts::APKPURE_DOWNLOAD_URL_REGEX).unwrap());

    futures_util::stream::iter(
        apps.into_iter().map(|app| {
            let (app_id, app_version) = app;
            let http_client = Rc::clone(&http_client);
            let re = Rc::clone(&re);
            let headers = headers.clone();
            let mp = Rc::clone(&mp);
            let mp_log = Rc::clone(&mp);
            async move {
                let app_string = match (&app_version, app_arch) {
                    (None, None) => {
                        mp_log.suspend(|| println!("Downloading {} from APKPure...", app_id));
                        app_id.to_string()
                    },
                    (None, Some(ref arch)) => {
                        mp_log.suspend(|| println!("Downloading {} arch {} from APKPure...", app_id, arch));
                        format!("{}@{}", app_id, arch)
                    },
                    (Some(ref version), None) => {
                        mp_log.suspend(|| println!("Downloading {} version {} from APKPure...", app_id, version));
                        format!("{}@{}", app_id, version)
                    },
                    (Some(ref version), Some(ref arch)) => {
                        mp_log.suspend(|| println!("Downloading {} version {} arch {} from APKPure...", app_id, version, arch));
                        format!("{}@{}@{}", app_id, version, arch)
                    },
                };
                if sleep_duration > 0 {
                    sleep(TokioDuration::from_millis(sleep_duration)).await;
                }
                let versions_url = Url::parse(&format!("{}{}", crate::consts::APKPURE_VERSIONS_URL_FORMAT, app_id)).unwrap();
                let versions_response = http_client
                    .get(versions_url)
                    .headers(headers)
                    .send().await.unwrap();
                if let Some(app_version) = app_version {
                    let regex_string = format!("[[:^digit:]]{}:(?s:.)+?{}", regex::escape(&app_version), crate::consts::APKPURE_DOWNLOAD_URL_REGEX);
                    let re = Regex::new(&regex_string).unwrap();
                    download_from_response(versions_response, Box::new(Box::new(re)), app_string, outpath, mp, all_variants).await;
                } else {
                    download_from_response(versions_response, Box::new(re), app_string, outpath, mp, false).await;
                }
            }
        })
    ).buffer_unordered(parallel).collect::<Vec<()>>().await;
}

async fn download_from_response(response: Response, re: Box<dyn Deref<Target=Regex>>, app_string: String, outpath: &Path, mp: Rc<MultiProgress>, all: bool) {
    let mp_log = Rc::clone(&mp);
    match response.status() {
        reqwest::StatusCode::OK => {
            let body = response.text().await.unwrap();
            let descriptors = download_descriptors(&re, &body, all);
            if descriptors.is_empty() {
                mp_log.println(format!("Could not get download URL for {}. Skipping...", app_string)).unwrap();
                return;
            }
            let count = descriptors.len();
            for (index, (kind, download_url)) in descriptors.iter().enumerate() {
                let fname = descriptor_file_name(&app_string, kind, index, count);
                download_file(download_url, &fname, &app_string, outpath, Rc::clone(&mp)).await;
            }
        },
        _ => {
            mp_log.println(format!("Invalid app response for {}. Skipping...", app_string)).unwrap();
        }
    }
}

async fn download_file(download_url: &str, fname: &str, app_string: &str, outpath: &Path, mp: Rc<MultiProgress>) {
    let mp_log = Rc::clone(&mp);
    match AsyncDownload::new(download_url, Path::new(outpath), fname).get().await {
        Ok(mut dl) => {
            let length = dl.length();
            let cb = match length {
                Some(length) => Some(progress_wrapper(mp)(fname.to_string(), length)),
                None => None,
            };

            match dl.download(&cb).await {
                Ok(_) => mp_log.suspend(|| println!("{} downloaded successfully!", fname)),
                Err(err) if matches!(err.kind(), TDSTDErrorKind::FileExists) => {
                    mp_log.println(format!("File already exists for {}. Skipping...", fname)).unwrap();
                },
                Err(err) if matches!(err.kind(), TDSTDErrorKind::PermissionDenied) => {
                    mp_log.println(format!("Permission denied when attempting to write file for {}. Skipping...", fname)).unwrap();
                },
                Err(_) => {
                    mp_log.println(format!("An error has occurred attempting to download {}.  Retry #1...", fname)).unwrap();
                    match AsyncDownload::new(download_url, Path::new(outpath), fname).download(&cb).await {
                        Ok(_) => mp_log.suspend(|| println!("{} downloaded successfully!", fname)),
                        Err(_) => {
                            mp_log.println(format!("An error has occurred attempting to download {}.  Retry #2...", fname)).unwrap();
                            match AsyncDownload::new(download_url, Path::new(outpath), fname).download(&cb).await {
                                Ok(_) => mp_log.suspend(|| println!("{} downloaded successfully!", fname)),
                                Err(_) => {
                                    mp_log.println(format!("An error has occurred attempting to download {}. Skipping...", fname)).unwrap();
                                }
                            }
                        }
                    }
                }
            }
        },
        Err(_) => {
            mp_log.println(format!("Invalid response for {}. Skipping...", app_string)).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options<'a>(pairs: &[(&'a str, &'a str)]) -> HashMap<&'a str, &'a str> {
        pairs.iter().copied().collect()
    }

    #[test]
    fn sdk_defaults_to_29_and_takes_a_numeric_override() {
        assert_eq!(sdk_header(&options(&[])), "29");
        assert_eq!(sdk_header(&options(&[("sdk", "36")])), "36");
        assert_eq!(http_headers(&options(&[("sdk", "36")]))["x-sv"], "36");
    }

    #[test]
    fn a_non_numeric_sdk_falls_back_to_29() {
        for bad in ["", "3x", "1000", "36\n"] {
            assert_eq!(sdk_header(&options(&[("sdk", bad)])), "29", "{bad:?}");
        }
    }

    #[test]
    fn all_variants_needs_an_explicit_true() {
        assert!(!all_variants(&options(&[])));
        assert!(!all_variants(&options(&[("all_variants", "no")])));
        assert!(all_variants(&options(&[("all_variants", "TRUE")])));
        assert!(all_variants(&options(&[("all_variants", "1")])));
    }

    const BODY: &str = "\u{12}1.2.3:\u{8}XAPKJ\u{1}\u{2}https://d.example.com/a.xapk?k=1\u{0} \
        \u{12}1.2.3:\u{8}XAPKJ\u{1}\u{2}https://d.example.com/b.xapk?k=2\u{0} \
        \u{12}1.2.3:\u{8}XAPKJ\u{1}\u{2}https://d.example.com/a.xapk?k=1\u{0} \
        \u{12}1.2.4:\u{8}APKJ\u{1}\u{2}https://d.example.com/c.apk\u{0}";

    fn version_regex(version: &str) -> Regex {
        Regex::new(&format!(
            "[[:^digit:]]{}:(?s:.)+?{}",
            regex::escape(version),
            crate::consts::APKPURE_DOWNLOAD_URL_REGEX
        ))
        .unwrap()
    }

    #[test]
    fn the_first_descriptor_alone_by_default() {
        let found = download_descriptors(&version_regex("1.2.3"), BODY, false);
        assert_eq!(found, vec![("XAPKJ".to_string(), "https://d.example.com/a.xapk?k=1".to_string())]);
    }

    #[test]
    fn every_distinct_descriptor_of_the_version_with_all_variants() {
        let urls: Vec<String> = download_descriptors(&version_regex("1.2.3"), BODY, true)
            .into_iter()
            .map(|(_, url)| url)
            .collect();
        assert!(urls.starts_with(&[
            "https://d.example.com/a.xapk?k=1".to_string(),
            "https://d.example.com/b.xapk?k=2".to_string(),
        ]));
        assert_eq!(urls.iter().filter(|url| url.ends_with("a.xapk?k=1")).count(), 1);
    }

    #[test]
    fn several_descriptors_get_numbered_file_names() {
        assert_eq!(descriptor_file_name("p@1@arm64-v8a", "XAPKJ", 0, 1), "p@1@arm64-v8a.xapk");
        assert_eq!(descriptor_file_name("p@1", "APKJ", 1, 2), "p@1.variant2.apk");
    }
}

pub async fn list_versions(apps: Vec<(String, Option<String>)>, options: HashMap<&str, &str>) {
    let http_client = Rc::new(reqwest::Client::new());
    let re = Rc::new(Regex::new(r"([[:alnum:]\.-]+):\([[:xdigit:]]{40,}").unwrap());
    let headers = http_headers(&options);
    let output_format = match options.get("output_format") {
        Some(val) if val.to_lowercase() == "json" => OutputFormat::Json,
        _ => OutputFormat::Plaintext,
    };
    let json_root = Rc::new(RefCell::new(match output_format {
        OutputFormat::Json => Some(HashMap::new()),
        _ => None,
    }));

    for app in apps {
        let (app_id, _) = app;
        let http_client = Rc::clone(&http_client);
        let re = Rc::clone(&re);
        let json_root = Rc::clone(&json_root);
        let output_format = output_format.clone();
        let headers = headers.clone();
        async move {
            if output_format.is_plaintext() {
                println!("Versions available for {} on APKPure:", app_id);
            }
            let versions_url = Url::parse(&format!("{}{}", crate::consts::APKPURE_VERSIONS_URL_FORMAT, app_id)).unwrap();
            let versions_response = http_client
                .get(versions_url)
                .headers(headers)
                .send().await.unwrap();

            match versions_response.status() {
                reqwest::StatusCode::OK => {
                    let body = versions_response.text().await.unwrap();
                    let mut versions = HashSet::new();
                    for caps in re.captures_iter(&body) {
                        if caps.len() >= 2 {
                            versions.insert(caps.get(1).unwrap().as_str().to_string());
                        }
                    }
                    let mut versions = versions.drain().collect::<Vec<String>>();
                    versions.sort();
                    match output_format {
                        OutputFormat::Plaintext => {
                            println!("| {}", versions.join(", "));
                        },
                        OutputFormat::Json => {
                            let mut app_root: HashMap<String, Vec<HashMap<String, String>>> = HashMap::new();
                            app_root.insert("available_versions".to_string(), versions.into_iter().map(|v| {
                                let mut version_map = HashMap::new();
                                version_map.insert("version".to_string(), v);
                                version_map
                            }).collect());
                            json_root.borrow_mut().as_mut().unwrap().insert(app_id.to_string(), json!(app_root));
                        },
                    }
                }
                _ => {
                    match output_format {
                        OutputFormat::Plaintext => {
                            eprintln!("| Invalid app response for {}. Skipping...", app_id);
                        },
                        OutputFormat::Json => {
                            let mut app_root = HashMap::new();
                            app_root.insert("error".to_string(), "Invalid app response.".to_string());
                            json_root.borrow_mut().as_mut().unwrap().insert(app_id.to_string(), json!(app_root));
                        },
                    }
                }
            }
        }.await;
    }
    if output_format.is_json() {
        println!("{{\"source\":\"APKPure\",\"apps\":{}}}", json!(*json_root));
    };
}
