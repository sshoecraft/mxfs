---
name: feedback-when-the-user-is-afk-take-the-recommended-default-never-ask
description: USER 2026-10-02 (angry): "stop asking me questions!!! i am AFK - assume recommended defaults". Decide with the recommended option; report the choice.
metadata:
  type: feedback
tags: [user-preference, autonomy]
---

During a long autonomous task (getting DRBD dual-primary working "100%"), the session raised three AskUserQuestion prompts for design forks:
- DRBD clean-retirement rule;
- libvirt hook install;
- pair-outage startup fencing.

The user replied: "OMG stop asking me questions!!! i am AFK - assume recommended defaults".

**Rule.** On a long task the user has handed over, do not stop to ask at design forks. Take the option you would have marked "(Recommended)", carry on, and list each decision taken that way, with its reason, in the final report so it can be reversed. This holds even where project rules allow a consult or a question. A design consult (ask_gpt) is still fine because it does not need the user. The project's hard prohibitions still apply: never reboot clyde, never run git unasked, never widen a timeout.
