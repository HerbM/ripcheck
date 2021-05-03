#![allow(incomplete_include)]
// use std::collections::HashMap;
use phf::phf_map;
// extern crate lazy_static;

std::include!("WireSharkNics.phf");

pub fn mac_to_vendor(mac: &str) -> String {
  let mut search = String::from(mac).to_uppercase();
  search.retain(|c| ('0'..='9').contains(&c) || ('A'..='F').contains(&c));
  for nibbles in std::array::IntoIter::new([9,7,6]) {
    if search.len() >= nibbles {
      if let Some(search) = search.get(..nibbles) {
        if let Some(value) = MAC_TO_VENDOR.get(search) {
          return value.to_string();
        }
      }
    }
  }
  "".to_string()
}

static _MAC_TO_VENDOR: phf::Map<&'static str, &str> = phf_map! {
    "loop"     => "Keyword::Loop",
    "continue" => "Keyword::Continue",
    "break"    => "Keyword::Break",
    "fn"       => "Keyword::Fn",
    "extern"   => "Keyword::Extern",
};

/*
Invoke-WebRequest -Uri "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf" -OutFile nicmanuf.txt
$WireSharkNics.Content -split "`n+" | Select -first 100

$PHF = $True
$OutFile = If ($PHF) { '.\src\WireSharkNics.phf' } Else { '.\src\WireSharkNics.txt' }
@(If ($PHF) {
  "static MAC_TO_VENDOR: phf::Map<&'static str, &str> = phf_map! {"
} Else {
  "lazy_static!{static ref MAC_TO_VENDOR: HashMap<&'static str, &'static str> = vec!["
}) > $OutFile

$WireSharkNics = Invoke-WebRequest -Uri "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf"
@(($WireSharkNics.Content -split "`n+").trim() -replace '\s*#.*$' |
  Where length -gt 0 |
  ForEach-Object {
    $Mac,$Man,$Void = $_ -split '\s+';
    [PSCustomObject]@{ MAC = $Mac; Vendor = $Man }
  } | ForEach-Object {
  $MAC, $Bits = $_.MAC -split '[/]+';
  if (!$Bits) { $Bits = 24 };
  $MAC = $MAC -replace ':';
  If ($True) {
    ##     "fn"       => "Keyword::Fn",
    "`"$($MAC.substring(0,($Bits/4)))`" => `"$($_.Vendor)`","
  } Else {
    "(`"$($MAC.substring(0,($Bits/4)))`", `"$($_.Vendor)`"),"
  }
}) >> $OutFile

@(If ($PHF) {
  "};"
} Else {
  "].into_iter().collect();"
}) >> $OutFile


$WireSharkNics = Invoke-WebRequest -Uri "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf"
$NicMacs = ($WireSharkNics.Content -split "`n+").trim() -replace '\s*#.*$' |
  Where length -gt 0 |
  ForEach-Object {
    $Mac,$Man,$Void = $_ -split '\s+';
    [PSCustomObject]@{ MAC = $Mac; Vendor = $Man }
  }
$NicMacs | ForEach-Object {
  $MAC, $Bits = $_.MAC -split '[/]+';
  if (!$Bits) { $Bits = 24 };
  $MAC = $MAC -replace ':';
  $MAC.substring(0,($Bits/4)) ,$Bits,$_.Vendor -join "`t"
}
If ($PHF) {
  "static MAC_TO_VENDOR_PHF: phf::Map<&'static str, &str> = phf_map! {"
} Else {
  "lazy_static!{static ref MAC_TO_VENDOR: HashMap<&'static str, &'static str> = vec!["
} > $OutFile



use phf::phf_map;
static MAC_TO_VENDOR: phf::Map<&'static str, Keyword> = phf_map! {
    "loop" => Keyword::Loop,
    "continue" => Keyword::Continue,
    "break" => Keyword::Break,
    "fn" => Keyword::Fn,
    "extern" => Keyword::Extern,
};
 */


