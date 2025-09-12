# hbctool with Hermes 96+ Support

This is a modified version of the original `hbctool` utility, patched to support modern versions of the Hermes bytecode (version 96 and newer) commonly found in recent React Native applications.

## The Problem

The original `hbctool` is an excellent utility for disassembling Hermes bytecode. However, as the Hermes engine has evolved, the bytecode format has changed significantly. The original tool does not support versions newer than 76, resulting in errors when trying to analyze `.apk` files from modern React Native apps. This makes it difficult for developers and security researchers to inspect the contents of `index.bundle` files.

## The Solution

This repository contains a modified version of `hbctool` where the core parsing and translation logic has been reverse-engineered and updated to be compatible with **Hermes Bytecode Version 96**.

Key changes include:
-   **Updated Parser:** The binary file parser (`parser.py`) has been rewritten to understand the new `BytecodeFileHeader` structure and correctly parse complex bitfields in sections like `Function Headers` and `String Tables`.
-   **Complete Opcode Definitions:** The opcode list (`opcode.json`) has been regenerated from a modern `BytecodeList.def` file to include all new, removed, and changed instructions.
-   **Robust Disassembler:** The translator (`translator.py`) is now more resilient and can gracefully handle unknown opcodes without crashing, making it usable even with future minor versions.

## How to Use

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Hamzamn19/hbctool-hermes96-support.git
    cd hbctool-hermes96-support
    ```

2.  **Install dependencies (if any):**
    The tool relies on a few standard Python packages. You can install them locally. It is recommended to use a virtual environment.
    ```bash
    pip install .
    ```

3.  **Run the tool:**
    Use the `hbctool` command as you normally would. For example, to disassemble a bundle file:
    ```bash
    hbctool disasm /path/to/your/index.android.bundle /path/to/output_folder
    ```

## Credits and Acknowledgements

This project would not be possible without the foundational work done by the original author of `hbctool`. This repository is a fork/modification intended to extend its functionality for newer bytecode versions.

**Please find the original project here: [https://github.com/bongtrop/hbctool]**
