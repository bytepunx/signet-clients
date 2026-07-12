//! Generated protobuf/tonic bindings for signet, from bytepunx/signet-proto.
//! Run `buf generate` to regenerate `src/gen`.

// Each base file ends with its own `include!` of the matching *.tonic.rs
// file, so only the base file needs including here.
pub mod signet {
    pub mod v1 {
        include!("gen/signet/v1/signet.v1.rs");
    }
}

pub mod admin {
    pub mod v1 {
        include!("gen/admin/v1/admin.v1.rs");
    }
}
