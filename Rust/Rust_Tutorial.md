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

# Organize Code
Rust code can be split into multiple `.rs` files:
each of them is called --> module

These modules must be kept together by a 'parent' Rust file, that can be:
- `main.rs` for applications
- `lib.rs` for a library
- `mod.rs` for sub-modules

## Examples
`dababase.rs` contains 2 submodules --> `project` and `person`
```
|- Cargo.toml
|- src
    |- main.rs
    |- database.rs
```

`src/database.rs`:
```rust
pub mod project {
    #[derive(Debug)]
    pub struct Project {
        pub name: String,
    }
}

pub mod person {
    use crate::database::project::Project;

    #[derive(Debug)]
    pub struct Person {
        pub name: String,
        pub project: Option<Project>,
    }
}
```

`src/main.rs`:
```rust
use crate::database::person::Person;
use crate::database::project::Project;

mod database;

fn main() {
    let project = Project {
        name: "Rust book".to_string(),
    };
    let person = Person {
        name: "Marcel".to_string(),
        project: Some(project),
    };

    println!("{:?}", person);
}
```
=>
- The `main.rs` <font color="#245bdb">must 'stitch'</font> the modules together using a `mod` statement
  => `mod database`

- The `pub` keyword in front of `struct` and `name` means that:
  we expose these items for use -->  **<font color="#245bdb">outside</font>** of the module

Code output:
```
Person { name: "Marcel", project: Some(Project { name: "Rust book" }) }
```

## More modules
If you want to keep each module in a file 
=> 
you can create subfolders in the `src` folders

### Example
```
|- Cargo.toml
|- src
    |- main.rs
    |- database
          |- mod.rs
          |- person.rs
          |- project.rs
```

in `src/database/mod.rs`:
```rust
pub mod person;
pub mod project;
```

In `src/main.rs` you'll have:
```rust

```

