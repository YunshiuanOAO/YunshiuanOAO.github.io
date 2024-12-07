# Welcome to MkDocs

For full documentation visit [mkdocs.org](https://www.mkdocs.org).

## Commands

* `mkdocs new [dir-name]` - Create a new project.
* `mkdocs serve` - Start the live-reloading docs server.
* `mkdocs build` - Build the documentation site.
* `mkdocs -h` - Print help message and exit.

## Project layout

    mkdocs.yml    # The configuration file.
    docs/
        index.md  # The documentation homepage.
        ...       # Other markdown pages, images and other files.


### Generic Content

=== "plaintext"

    This is some plaon text 

=== "Unorfered list"   
    * firts 
    * second 
    * third 

=== "Orderd List"

    1. first
    2. second
    3. third item 

=== "Python List"
    ```py title="Hello.py" linenums="1"
    print("Hello Python")
    ```

!!! note "Title of the callout"
    hello world

??? info "Title of info"
    hello world