
# Titolo 1
##  Titolo 2
###  Titolo 3
####  Titolo 4

Paragrafo

[[Notes_ETH | Nome Internal Link]]
[[Notes_ETH#Capstones]]     (nota che linka direttamente ad un heading specifico)

[External Link](https://help.obsidian.md/Editing+and+formatting/Basic+formatting+syntax) 

- List
%% Visibile solo in edit mode (per creare una lista usa il trattino -) %%   

---

> [!NOTE] Esempio Callout
> Guarda in fondo per vedere tutti i possibili collout
> [[how_to#Possibili Callout]]

---
```rust
use thiserror::Error;
#[derive(Error, Debug, Clone)]

pub enum Error {
    #[error("Usage: scanner <domain.com>")]
    CliUsage,
}
```

| Prova| Prova2|
| --- | --- |
|aaa  | bbbb |

## Possibili Callouts 
![[Pasted image 20240213173038.png]]