INTRODUCTION:
------------
Hack-auto is an automation tool that helps coordinate multiple hacking tools, allowing users to perform tasks without the difficulty of memorizing complex commands from different tools.

It includes unique features such as editing, appending, and deleting script code blocks at runtime.

Additionally, the tool provides a feature designed for users who are not very familiar with Bash but are comfortable with Python. This feature allows them to write Python code seamlessly without difficulty.

The feature, called embedded Python, enables Python code to run directly within a Bash script, thereby improving workflow and integration between Bash and Python.

Here is how embedded Python looks:
----------------------------------
Embed Python inside Bash.

#!/bin/bash

echo "Running bash script code..." # this is a bash line

python3 << 'EOF'
import os
print("Hello from embedded Python")
print("Current directory:", os.getcwd())
EOF

echo "Back to Bash" # this is a bash line

They will be able to write Python code without worrying about adding ‘here-doc’ redirection syntax as shown above [ <<EOF.....EOF ].

To test the project, follow these steps:
----------------------------------------
1.Download the script file.

2.Locate the folder where the script was downloaded (usually the Downloads folder).

3.Enable execution permission using the command inside quotation marks: 'sudo chmod +x hack-auto.sh'

4.Run the script using the command inside quotation marks: 'bash hack-auto.sh' Once executed, the log in time and ip address will appear, indicating that the script is running.

5.Feel free to explore the project and test its different functionalities.
