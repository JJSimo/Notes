- create master repo
- clone it
- create a sub repo
- inside the master repo:
  `git submodule add https://github.com/JJSimo/submodule_name`

- `git add .`
- `git commit -m "add submodule"`
- `git push origin main`

### Push
- edit project
- `git add .`
- `git commit -m "edit..."`
- `git branch --show-current`         es output -->  `main`
- `git push origin main`
- `cd master repo`
- `git add path to submodule
- `git commit -m "update submodule..."`
- `git push origin main`
### Update all submodule
`git submodule update --init
### pull all changes in the repo including changes in the submodules
`git pull --recurse-submodules`