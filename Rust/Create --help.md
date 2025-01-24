To create a help section you can use -->  `clap`

# Example
Example:
`cargo add clap --features derive`

```rust
use clap::Parser;

///  !!! Write program description here !!!
#[derive(Parser, Debug)]
#[command(version)]         
struct Args {
    /// Name of the person to say hello
    #[arg(short, long)]
    name: String,

    /// Number of times to say hello
    #[arg(short, long, default_value_t = 1)]
    count: u8,
}

fn main() {
    let args = Args::parse();
    let num_say_hello = args.count;

    for _ in 0..num_say_hello {
        println!("Hello {}!", args.name);
    }
}
```

=>
- `#[command(version)] ` -->  it will add automatically the `version` argument
  
- `#[arg(short, long, default_value_t = 1)]`
  count argument can be written short or long and the default value is 1
  =>
  you can write:
	- `-c 2`
	- `--count 2`
	- `-c` or `--count` (and it will be set to 1)

# Example output
--help:
![[Pasted image 20241230172658.png]]
normal execution
![[Pasted image 20241230172728.png]]

count argument:
![[Pasted image 20241230172830.png]]