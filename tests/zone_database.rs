//! Where a time zone's rules come from. This is the only test in the file, and it has to stay
//! that way: the database is found once per process, so `TZDIR` must be set before anything
//! has asked for a zone.

use chrono::{Offset, TimeZone, Utc};
use grizzle_local::zone::Tz;

#[test]
fn the_systems_rules_win_and_the_built_in_copy_fills_the_gaps() {
    let kolkata = std::path::Path::new("/usr/share/zoneinfo/Asia/Kolkata");
    if !kolkata.exists() {
        return; // no system database to borrow a zone file from
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("America")).unwrap();
    // This "system" says Denver keeps Kolkata's time, and has never heard of US/Mountain.
    std::fs::copy(kolkata, dir.path().join("America/Denver")).unwrap();
    std::env::set_var("TZDIR", dir.path());
    let offset = |name: &str| {
        let tz: Tz = name.parse().unwrap();
        Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap().with_timezone(&tz).offset().fix().local_minus_utc()
    };
    assert_eq!(offset("America/Denver"), 5 * 3600 + 1800, "the system's database is asked first");
    assert_eq!(offset("US/Mountain"), -7 * 3600, "what it lacks comes from the copy in the binary");
}
