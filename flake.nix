{
  description = "wgautomesh";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/a3073c49bc0163fea6a121c276f526837672b555";
  inputs.cargo2nix = {
    # As of 2022-10-18: two small patches over unstable branch, one for clippy and one to fix feature detection
    url = "github:Alexis211/cargo2nix/a7a61179b66054904ef6a195d8da736eaaa06c36";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, cargo2nix }:
  let
    pkgs = import nixpkgs {
      system = "x86_64-linux";
      overlays = [ cargo2nix.overlays.default ];
    };
    packageFun = import ./Cargo.nix;
    rustVersion = "1.63.0";

    compile = args: compileMode:
      let
        packageSet = pkgs.rustBuilder.makePackageSet ({
          inherit packageFun rustVersion;

          # Config to build static binaries
          target = "x86_64-unknown-linux-musl";
          codegenOpts = {
            "x86_64-unknown-linux-musl" =
              [ "target-feature=+crt-static" "link-arg=-static-pie" ];
          };
        } // args);
      in
        packageSet.workspace.wgautomesh {
          inherit compileMode;
        };
  in
  {
    test.x86_64-linux.wgautomesh = compile { release = false; } "test";
    debug.x86_64-linux.wgautomesh = compile { release = false; } "build";
    packages.x86_64-linux.wgautomesh = compile { release = true; } "build";
    packages.x86_64-linux.default = self.packages.x86_64-linux.wgautomesh;
  };
}
