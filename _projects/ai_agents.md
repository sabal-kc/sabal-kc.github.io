---
layout: page
title: Moodle/Canvas AI Agent
description: Autonomous LMS agent that logs into Moodle and Canvas, detects assignments, and submits work through a Playwright-driven tool loop.
img: assets/img/canvas-logo.png
importance: 1
category: work
backURL: true
---

This project explores how autonomous AI agents move beyond chat interfaces into real education platforms. The agent can log into Moodle and Canvas, inspect available assignments, and complete submission workflows through browser automation.

The work uses LangGraph, Python, and Playwright to build an agentic tool loop that can navigate LMS pages, reason over page state, and execute actions under realistic constraints. It also studies the risk side of the same capability: once agents can act inside institutional systems, guardrails, monitoring, and clear responsibility boundaries become essential.

<b>Key work:</b>

<ul>
  <li>Built a LangGraph agent that automates LMS login, assignment discovery, and assignment submission through Playwright.</li>
  <li>Compared multiple LLMs for Moodle and Canvas login workflows using cost, token usage, and latency measurements.</li>
  <li>Evaluated LangGraph and Autogen as orchestration frameworks for autonomous education workflows.</li>
  <li>Packaged the agent as a containerized long-running service with scheduled execution and LangSmith logging.</li>
</ul>

<section style="text-align:center;">
  <img src="/assets/img/canvas-logo.png" style="width:520px; max-width:100%; height:auto; margin:10px;" />
</section>
