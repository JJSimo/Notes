# Installation
[link](https://doc.rust-lang.org/book/ch01-01-installation.html)

-----
Linux:
```bash
sudo apt install gcc
curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | sh

# Restart shell, then check with:
rustc --version
```

Windows:
- follow this [guide](https://github.com/bycloudai/InstallVSBuildToolsWindows?tab=readme-ov-file)
=> 
- first install `c++` building tool from [here](https://visualstudio.microsoft.com/it/visual-cpp-build-tools/)
- Install as in the image![[Pasted image 20241227181057.png]]
- [link to download exe](https://www.rust-lang.org/tools/install)
- Open a terminal and test with `rustc --version`

## Update
`rustup update`
# Create, build and run a project
- `cargo new <project_name>` -->  create a project called "project_name"
- `cargo build` -->  build the project
- `cargo run` -->  compile and run the project
- `cargo check` -->  compile without execute



