use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
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

/// The parts of `body` that belong to the records of exactly `version`, in
/// the order APKPure lists them. Each runs from the end of a record's version
/// marker to the start of the next record's, so it holds every descriptor of
/// that record and none of another version's.
fn version_records<'a>(marker: &Regex, body: &'a str, version: &str) -> Vec<&'a str> {
    let markers: Vec<_> = marker.find_iter(body).collect();
    markers
        .iter()
        .enumerate()
        .filter(|(_, m)| names_version(&body[..m.start()], version))
        .map(|(i, m)| {
            let end = markers.get(i + 1).map_or(body.len(), |next| next.start());
            &body[m.end()..end]
        })
        .collect()
}

/// True when `prefix`, the text before a version marker, ends with the whole
/// version string `version`. APKPure frames the string with its one-byte
/// length, so `2.3` does not match a `1.2.3` record; a version too long for a
/// one-byte length cannot be checked that way and only has to match.
fn names_version(prefix: &str, version: &str) -> bool {
    let Some(rest) = prefix.strip_suffix(version) else {
        return false;
    };
    match u8::try_from(version.len()) {
        Ok(0) => false,
        Ok(len @ 1..=127) => rest.ends_with(char::from(len)),
        _ => true,
    }
}

/// The (kind, URL) of each download descriptor `re` finds in `regions`, in
/// the order APKPure lists them, without repeats; only the first unless `all`.
fn download_descriptors<'a>(re: &Regex, regions: impl IntoIterator<Item = &'a str>, all: bool) -> Vec<(String, String)> {
    let mut seen = HashSet::new();
    let mut descriptors = Vec::new();
    for region in regions {
        for caps in re.captures_iter(region) {
            let (Some(kind), Some(url)) = (caps.get(1), caps.get(2)) else {
                continue;
            };
            if seen.insert(url.as_str().to_string()) {
                descriptors.push((kind.as_str().to_string(), url.as_str().to_string()));
                if !all {
                    return descriptors;
                }
            }
        }
    }
    descriptors
}

/// The descriptors to download from a versions response `body`: for an exact
/// `version`, those in its records (every one if `all`, else the first); for
/// the latest version, the first one listed.
fn select_descriptors(download: &Regex, marker: &Regex, body: &str, version: Option<&str>, all: bool) -> Vec<(String, String)> {
    match version {
        Some(version) => download_descriptors(download, version_records(marker, body, version), all),
        None => download_descriptors(download, [body], false),
    }
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
    let marker = Rc::new(Regex::new(crate::consts::APKPURE_VERSION_MARKER_REGEX).unwrap());

    futures_util::stream::iter(
        apps.into_iter().map(|app| {
            let (app_id, app_version) = app;
            let http_client = Rc::clone(&http_client);
            let re = Rc::clone(&re);
            let marker = Rc::clone(&marker);
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
                let select = |body: &str| select_descriptors(&re, &marker, body, app_version.as_deref(), all_variants);
                download_from_response(versions_response, select, app_string, outpath, mp).await;
            }
        })
    ).buffer_unordered(parallel).collect::<Vec<()>>().await;
}

async fn download_from_response(response: Response, select: impl Fn(&str) -> Vec<(String, String)>, app_string: String, outpath: &Path, mp: Rc<MultiProgress>) {
    let mp_log = Rc::clone(&mp);
    match response.status() {
        reqwest::StatusCode::OK => {
            let body = response.text().await.unwrap();
            let descriptors = select(&body);
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

    /// A version record as APKPure frames it: the length-prefixed version
    /// string, its SHA-1 marker, then one descriptor per `(kind, url)`.
    fn record(version: &str, descriptors: &[(&str, &str)]) -> String {
        let mut record = format!("\u{1a}\u{0}2{}{}:({}\u{8}", char::from(version.len() as u8), version, "ab".repeat(20));
        for (kind, url) in descriptors {
            record.push_str(&format!("B\u{4}{kind}\u{fffd}\u{3}{url}\u{0}"));
        }
        record
    }

    const A: &str = "https://d.example.com/a.xapk?k=1";
    const B: &str = "https://d.example.com/b.apk?k=2";
    const C: &str = "https://d.example.com/c.xapk?k=3";
    const NEWER: &str = "https://d.example.com/newer.apk";
    const OLDER: &str = "https://d.example.com/older.apk";

    fn body() -> String {
        [
            record("1.2.4", &[("APKJ", NEWER)]),
            record("1.2.3", &[("XAPKJ", A), ("APKJ", B)]),
            record("1.2.3", &[("XAPKJ", C), ("XAPKJ", A)]),
            record("2.3", &[]),
            record("1.2.2", &[("APKJ", OLDER)]),
        ]
        .concat()
    }

    fn select(version: Option<&str>, all: bool) -> Vec<(String, String)> {
        let download = Regex::new(crate::consts::APKPURE_DOWNLOAD_URL_REGEX).unwrap();
        let marker = Regex::new(crate::consts::APKPURE_VERSION_MARKER_REGEX).unwrap();
        select_descriptors(&download, &marker, &body(), version, all)
    }

    fn urls(descriptors: Vec<(String, String)>) -> Vec<String> {
        descriptors.into_iter().map(|(_, url)| url).collect()
    }

    #[test]
    fn the_first_descriptor_of_the_version_alone_by_default() {
        assert_eq!(select(Some("1.2.3"), false), vec![("XAPKJ".to_string(), A.to_string())]);
    }

    #[test]
    fn every_distinct_descriptor_of_every_record_of_the_version_with_all_variants() {
        assert_eq!(urls(select(Some("1.2.3"), true)), vec![A, B, C]);
        assert_eq!(select(Some("1.2.3"), true)[1].0, "APKJ");
    }

    #[test]
    fn another_versions_descriptors_are_never_taken() {
        assert!(select(Some("2.3"), true).is_empty());
        assert!(select(Some("1.2"), true).is_empty());
        assert!(select(Some("9.9.9"), false).is_empty());
        assert_eq!(urls(select(Some("1.2.2"), true)), vec![OLDER]);
    }

    #[test]
    fn the_latest_version_takes_the_first_descriptor_listed() {
        assert_eq!(urls(select(None, true)), vec![NEWER]);
    }

    #[test]
    fn a_version_must_carry_its_own_length_prefix() {
        assert!(names_version("\u{0}2\u{5}1.2.3", "1.2.3"));
        assert!(!names_version("\u{0}2\u{5}1.2.3", "2.3"));
        assert!(!names_version("\u{0}2\u{6}11.2.3", "1.2.3"));
        assert!(!names_version("\u{0}2\u{0}", ""));
        let long = "1".repeat(200);
        assert!(names_version(&format!("x{long}"), &long));
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
