## Building the devcontainer

The `.devcontainer/Dockerfile` is used to built a prebuild container to speed up the starting process of the actual devcontainer itself.
When you update the Dockerfile, make sure you rebuild it with:

```bash
$ docker build -t cloudkrafter/ansible-devcontainer:latest -f .devcontainer/nexus-collection/Dockerfile .
```

## Launching the Devcontainer:

1. Open the project in Visual Studio Code.
2. When prompted, select "Reopen in Container" to launch the development container using the configuration defined in `devcontainer.json`.

## Contributing to the devcontainer

1. Clone the repository to your local machine:
```bash
git clone git@github.com:CloudKrafter/nexus-ansible-collection.git
cd nexus-ansible-collection
```
2. Make proposed changes
- Edit the `devcontainer.json`, `Dockerfile`, or `post-create.sh` files as needed to update the development environment.

For example, to add a new VS Code extension, update the `devcontainer.json` file:
```json
"customizations": {
  "vscode": {
    "extensions": [
      "ms-azuretools.vscode-docker",
      "redhat.ansible",
      "ms-python.python",
      "your-new-extension"
    ]
  }
}
```

3. Test your changes
(Re)build and test the development container locally to ensure your changes work as expected.

4. Commit and push changes to GitHub.
