pub struct EmbeddedAsset {
    pub id: &'static str,
    pub filename: &'static str,
    pub bytes: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/embedded_assets.rs"));

pub fn get(id: &str) -> Option<&'static EmbeddedAsset> {
    EMBEDDED.iter().find(|asset| asset.id == id)
}
