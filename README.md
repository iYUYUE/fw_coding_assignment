# Illumio Coding Assignment

## Implementation
### Normal Firewall
I first worked out an O(n) time rule matching function by going through each rule until one with matching IP interval and port interval is found.
### Tree Firewall
Then, I realized that, for large internet traffic,
1. O(n) is not good enough;
2. the firewall is read-heavy and will not reload the rule set very often.

Therefore, I did a bit of research and found what I need, an augmented Interval Tree (https://www.cs.cmu.edu/~ckingsf/bioinfo-lectures/intervaltrees.pdf). This algorithm gives O(log n) time complexity when the tree is balanced and the tree takes O(n log n) time to build. I implemented the tree-based rule matching function following the slide.
## Test
### Unit test
Because of the time, I only did a few unit tests on the **accept_packet()** function in ***fw.py***.
### Random test
I implemented a random test in ***test.py*** to
1. Check the consistency between the Normal and Tree Firewall. Since the logic of the Normal Firewall is extremely simple, it can be used as an auto-judge for the Tree Firewall.
2. Evaluate and compare the performance between the Normal and Tree Firewall
### Random test output
```
The results are identical
normal_fw_load_time 0 s
normal_fw_test_time 43 s
normal_fw_test_speed 2286 q/s
tree_fw_load_time 0 s
tree_fw_test_time 0 s
tree_fw_test_speed 104186 q/s
```
## To-do
* unbalanced random test
* tree rotation
# Teams of interest
I feel excited about the works that are being done in all three teams and I love to learn new technologies if the need arises. I want to learn more about the teams to make a choice. Thanks.
