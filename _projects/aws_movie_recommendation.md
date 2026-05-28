---
layout: page
title: AWS Cloud-Based Movie Recommendation System
description: Cloud-native movie recommendation app with Go microservices, React, AWS infrastructure, SageMaker recommendations, and LLM-powered suggestions.
img: assets/img/movierec-banner.png
importance: 2
projURL: https://findamovie.online/
github: https://github.com/findamovieforme/movies-service
category: work
backURL: true
---

This project is a cloud-native movie recommendation system with a web frontend, authenticated user flows, Go microservices, ML-powered recommendations, and natural-language movie search. The deployed site is available at <a href="https://findamovie.online/" target="_blank" rel="noopener noreferrer">findamovie.online</a>.

Users can sign up, browse and search movies, like titles, and receive recommendations from a KNN model served through SageMaker. The app also supports AI-powered prompts through Gemini for requests such as finding movies with a similar story, mood, or theme.

<b>Architecture:</b>

<ul>
  <li><b>Frontend:</b> React web app deployed on AWS Amplify.</li>
  <li><b>Auth:</b> Amazon Cognito issues ID tokens for protected API requests.</li>
  <li><b>API:</b> API Gateway routes authenticated traffic through an Application Load Balancer.</li>
  <li><b>Backend:</b> Go <code>movies-service</code> and <code>users-service</code> deployed on Amazon ECS with Fargate and EC2 comparison work.</li>
  <li><b>Data and ML:</b> DynamoDB stores user preferences, TMDB powers catalog data, S3 stores model artifacts, and SageMaker serves recommendation inference.</li>
  <li><b>Ops:</b> ECR stores service images and CloudWatch supports logs and monitoring.</li>
</ul>

<section style="text-align:center;">
  <img src="/assets/img/aws-movie-arch.png" style="width:760px; max-width:100%; height:auto; margin:10px;" />
  <img src="/assets/img/aws-movie-auth-flow.png" style="width:760px; max-width:100%; height:auto; margin:10px;" />
</section>
