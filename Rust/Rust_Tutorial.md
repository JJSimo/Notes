- [Installation](#Installation)
	- [Update](#Update)
- [Create, build and run a project](#Create,%20build%20and%20run%20a%20project)
- [Data types](#Data%20types)
- [Organize Code](#Organize%20Code)
	- [Examples](#Examples)
	- [More modules](#More%20modules)
		- [Example](#Example)
	- [Workspaces](#Workspaces)
		- [Example](#Example)
		- [Importing name abbreviation](#Importing%20name%20abbreviation)
	- [Importing Crates](#Importing%20Crates)
		- [Manually import](#Manually%20import)
		- [Using cargo](#Using%20cargo)
		- [Importing from git](#Importing%20from%20git)
		- [Importing only some features](#Importing%20only%20some%20features)

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

# Data types
`i8` -->  <span style="color:rgb(24, 175, 40)">signed</span> n° of 8 bits
       => 
       it goes from -128 to 127 

`u8` -->  <span style="color:rgb(24, 175, 40)">unsigned</span> n° of 8 bits => 0 to 255

Then:
- `i16` or `u16`
- `i32` or `u32`
- `i64` or `u64`
- `i128` or `u128`

- `f32` and `f64` -->  n° with digital points
- `str` -->  strings
- `bool`

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
use crate::database::person::Person; 
use crate::database::project::Project; 

mod database;

fn main() {

}
```

## Workspaces
set of packages that share the same _Cargo.lock_ and output directory

### Example
We split `database` so that will be a <span style="color:rgb(24, 175, 40)">reusable</span> library
=>
structure:
```
|- Cargo.toml
|- database_lib
|   |- Cargo.toml
|   |- src
|       |- lib.rs
|       |- person.rs
|       |- project.rs
|- my_project
    |- Cargo.toml
    |- src
        |- main.rs
```

 Top-level `Cargo.toml`:
```rust
[workspace]
members = [
    "database_lib",         // database library
    "my_project",
]
resolver = "2"
```

`Cargo.toml` in the `database_lib`:
```rust
[package]
name = "database_lib"
version = "0.1.0"
edition = "2021"

[dependencies]
```

`Cargo.toml` in the `my_project`:
```rust
[package]
name = "my_project"
version = "0.1.0"
edition = "2021"

[dependencies]
database_lib = { path = "../database_lib" }
```

The `lib.rs` would not include a `main` functio:
but instead a -->  `pub mod` statement for each module:
```rust
pub mod person;
pub mod project;
```

### Importing name abbreviation
In the main function you can:
- assign a name to a module:
```rust
use crate::database::person as prs;
```

- assign a name to a specific type:
```rust
use crate::database::person::Person as Someone;
```

## Importing Crates
To import 3rd party creates into your app:
- edit the `Cargo.toml` file under `[dependencies]` section
=>
### Manually import
```rust
[dependencies] 
rand = "0.7.3"
```

### Using cargo
```rust
cargo add rand
```

### Importing from git
```rust
[dependencies]
kp-lib-rs = { git = "https://bitbucket.forge.somewhere.com/scm/someservice/rust_common.git", tag = "v0.0.555" }
```

### Importing only some features
```rust
[dependencies]
serde = { version = "1.0.106", features = ["derive", "limit
"] }
```
