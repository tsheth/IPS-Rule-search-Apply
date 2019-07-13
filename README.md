# Search IPs rules with recommendable filed "No" and apply to policy

[![License](https://img.shields.io/badge/License-Apache%202-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This module shows how to use the Deep Security API to retrieve the IPS rules which has "recommendable" field set to "No" or "disabled".



## Get started

### Install dependencies

You will need Python 3 and [pipenv](https://github.com/pypa/pipenv) to install the dependencies for this project.
install python 3.7 and pip prior to executing bellow command.
```sh
$ pip install requirements.txt

```

### Usage

  Step 1: Deep security API key credentials are stored in "properties.json" file.
  ```json
    {
 	"url": "https://app.deepsecurity.trendmicro.com/api",
 	"secretkey": "F1AAE59B376A:P/mygoaZe6XyNhnqKNGxyxKxoI4Xv+GDfjHnYaRs060="
    }
```
  
  Step 2: Execute bellow command to apply all required rule to policy 
```text
usage: 
 main.py [-h] [--policy_id POLICY_ID]
                              
 example: py main.py --policy-id 1

List vulnerabilities found in scans

positional arguments:
  --policy-id           Enter the numeric policy id :
                        example: 1
```
