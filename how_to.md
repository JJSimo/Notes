
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
> [[how_to#Possibili Callouts]]

---
```rust
use thiserror::Error;
#[derive(Error, Debug, Clone)]

pub enum Error {
    #[error("Usage: scanner <domain.com>")]
    CliUsage,
}
```

| Prova | Prova2 |     |
| ----- | ------ | --- |
| aaa   | bbbb   |     |
|       |        |     |

### Change Heading Color
- Right click on the project folder > Show in System Explorel
- Create "snippets" folder
- Create file .css (es Simo-Colored Headings.css)
```css
.cm-header-1 {color: #00aaf6; }
.cm-header-2 {color: #00aaf6; }
.cm-header-3 {color: #00aaf6; }
.cm-header-4 {color: #00aaf6; }
.cm-header-5 {color: #00aaf6; }
.cm-header-6 {color: #00aaf6; }
```
- Open Settings > Appearance > CSS snippets > enable Simo-Colored Headingss
-----
## Plugins
Settings > Community Plugins > Browse
Then enable the plugin
Restart the application when you changed something
![[Pasted image 20240216135015.png]]
### Colored Text
#### Colors
![[Pasted image 20240214113010.png]]   
![[Pasted image 20240214113051.png]]
![[Pasted image 20240214113110.png]]
![[Pasted image 20240214113120.png]]
![[Pasted image 20240214113129.png]]
![[Pasted image 20240214113138.png]]

Go to Settings > Hotkeys > Colored Text
![[Pasted image 20240214113604.png]]
---- 
### Git
[Guida](https://forum.obsidian.md/t/the-easiest-way-to-setup-obsidian-git-to-backup-notes/51429) 
Per commit ->    CTRL + P
			   cerca "backup"

---

## Possibili Callouts 
![[Pasted image 20240213173038.png]]