Software Restriction Policies
=============================
Driver + control program to restrict which programs can be started.

Driver
------
The driver calls the function `PsSetCreateProcessNotifyRoutineEx()` to register a callback to be notified when a process is about to be created.

When the callback is called, the driver sends a message to the control program with the path of the executable and waits for the response, which might be allowed or not allowed.

If the control program is not running, the program will be allowed.


Control program
---------------
The control program accepts several commands:

```
Usage: SoftwareRestrictionPoliciesClient.exe [OPTIONS] <command> [<filename>]

Commands:
        run
        print-signers
        print-hash
        query


Options:
        --signers <filename>
        --hashes <filename>
        --paths <filename>
        --all-signers

```

The command `run` makes the program run in a loop waiting for messages from the driver.

The command `print-signers <filename>` displays the signers of the file `<filename>` (if any).

The command `print-hash <filename>` displays the hash of the file `<filename>`.

The command `query <filename>` displays whether the executable `<filename>` would be allowed.


A program will be allowed if:
* The program is in the Windows catalog.
* The program is signed and either the option `all-signers` has been specified or the signer has been added to the file of signers (option `--signers <filename>`).
* The program's hash has been added to the file of hashes (option `--hashes <filename>`).
* The program has been added to the file of paths, or one of its parent directories (option `--paths <filename>`).


Options:

Comments are allowed in the files, they must start at the beginning of the line and start with the character `#`.

* `--signers <filename>`: You can specify a file containing allowed signers.
* `--hashes <filename>`: You can specify a file containing allowed hashes.
* `--paths <filename>`: You can specify a file containing allowed paths, either file names or directories. If you specify a directory, all the executables under any subdirectory will be allowed.
