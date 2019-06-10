# What is this?
This is a little helper program to check if we're having missing or unused permissions in
our JSON policy file. The policy file `policy.json` is in AWS format and describes all required
permissions for a role. The other required file is `event_history.json` which is expected to
be an exported (as JSON) event collection of AWS CloudTrail.
The program then first loads the policy file, then the event history and after that dumps all
permissions to the console, which are found in the events but not in the policy and vice versa.

Olli, 2019/06/10
