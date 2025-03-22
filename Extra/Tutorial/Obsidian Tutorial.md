
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
> [[Obsidian Tutorial#Possibili Callouts]]

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
- Right click on the Obisidian Vault folder > Show in System Explorel
- open .obsidian > snippets
- Create file .css (es Simo-Colored-Headings.css)
```css
.cm-header-1 {color: #00aaf6; }
.cm-header-2 {color: #00aaf6; }
.cm-header-3 {color: #00aaf6; }
.cm-header-4 {color: #00aaf6; }
.cm-header-5 {color: #00aaf6; }
.cm-header-6 {color: #00aaf6; }
```
- Open Settings > Appearance > CSS snippets > enable Simo-Colored Headingss

==Code color:==
```css
.cm-header-1 {color: #00aaf6; }
.cm-header-2 {color: #00aaf6; }
.cm-header-3 {color: #00aaf6; }
.cm-header-4 {color: #00aaf6; }
.cm-header-5 {color: #00aaf6; }
.cm-header-6 {color: #00aaf6; }

.cm-s-obsidian span.cm-inline-code {
    color: #e55957;
}
```
-----
## Plugins
Settings > Community Plugins > Browse
Then enable the plugin
Restart the application when you changed something
![[Pasted image 20250322105059.png]]
### Colored Text
#### Colors
![[Pasted image 20240214113010.png|300]]   
![[Pasted image 20240214113051.png|300]]
![[Pasted image 20240214113110.png|300]]
![[Pasted image 20240214113120.png|300]]
![[Pasted image 20240214113129.png|300]]
![[Pasted image 20240214113138.png|300]]

Go to Settings > Hotkeys > Colored Text
![[Pasted image 20240214113604.png]]
---- 
### Git
[Guida](https://forum.obsidian.md/t/the-easiest-way-to-setup-obsidian-git-to-backup-notes/51429) 
Repo must be public -->  (only after cloning it you can change the visibility)

> [!warning] 
> Now you have to use `Commit-and-sync` instead of `backup`:
> 
> ![[Pasted image 20250310093545.png]]

# BACKUP Linux
- Open git and run the `Bash/Installer/install.sh`
- To edit the shell:
	- `sudo apt install zsh -y`
	- `chsh -s $(which zsh)`
	- `sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"`
	- install in VSCODE the `WSL` extension
	- `git clone git://github.com/zsh-users/zsh-autosuggestions ~/.oh-my-zsh/custom/plugins/zsh-autosuggestions`
	- `git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting`
	- code .zshrc
	- Search -->   `plugins=...`
	- Edit with:
	  `plugins=(`
          `zsh-autosuggestions`
          `zsh-syntax-highlighting`
      `)`   
	- Logout and re-enter 

  - Shell theme --> https://github.com/romkatv/powerlevel10k?tab=readme-ov-file


---

## Possibili Callouts 
![[Pasted image 20240213173038.png]]