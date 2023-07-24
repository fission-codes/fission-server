fn main() {
    println!("cargo:rerun-if-changed=fission-server/migrations");
}
