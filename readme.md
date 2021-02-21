# BESTIE Go Implementation


///// Curves
Since the MIRACL Core library does not support curves as objects, each curve has its own implementation. The following curves were used: BN254, BN462, BLS24-479, and BLS48-581.

///// Folder Structure
There are four folders, each containing similar files for a specific curve (see folder name)

|
|- BN254
|   |- algBN254                 // Contains the BESTIE algorithms
|   |- testInput.go             // Simple console app running BESTIE on user input (go file)
|   |- testInput.exe            // Simple console app running BESTIE on user input (compiled for Windows)
|   |- testInput.exec           // Simple console app running BESTIE on user input (compiled for Mac)
|   |- testParameters.go        // Test run to show all parameters for fixed id (go file)
|   |- testParameters.exe       // Test run to show all parameters for fixed id (compiled for Windows)
|   |- testParameters.exec      // Test run to show all parameters for fixed id (compiled for Mac)
|   |- testPerformance.go       // Test run to check performance for fixed id (go file)
|   |- testPerformance.exe      // Test run to check performance for fixed id (compiled for Windows)
|   |- testPerformance.exec     // Test run to check performance for fixed id (compiled for Mac)
|
|- BN462
| ... 


///// Running Executables
Each folder contains the original go files as well as compiled executable versions. 
If on Mac, simply running or double-clicking on those files (.exec file ending) will open them in terminal.
On Windows, please open Command Prompt, cd to directory of files and type 'cmd /k filename.exe', replacing filename with desired executable. This is to ensure the Command Window does not close right after the program is done and the results stay visible.

///// Testing Go Files
If you would like to change Parameters (such as ID, CL, RL etc.) in one of the go files, simply do so and run them from the console with the command 'go run *.go'. This ensures the file has all necessary functions available. You might need to comment/uncomment main functions where necessary, as there can only be one main function per package at all times. 

///// Remarks
Please note that for unidentified reasons, the executable files sometimes refuse to work. 
In that case, simply close the terminal window and try again.