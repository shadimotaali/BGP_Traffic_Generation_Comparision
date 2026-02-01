# BGP_Traffic_Generation_Comparision
Synthetic BGP traffic generation and evaluation for anomaly detection. Implements a consensus-based labeling pipeline on RIPE RIS data, benchmarks different generators (SMOTE, Copula, GANs, Scapy), and evaluates fidelity and detection utility under cross-collector and cross-incident distribution shifts.

## 📌 Overview

Machine learning-based BGP anomaly detection is severely limited by the scarcity of labeled training data. This repository provides a **systematic framework for generating, evaluating, and validating synthetic BGP traffic** using real RIPE RIS data.

The project:
- Builds **high-confidence labels** using a consensus of unsupervised detectors
- Benchmarks **13 synthetic data generators** across five families
- Evaluates **distributional fidelity, protocol realism, and detection utility**
- Tests **generalization under cross-collector and cross-incident shifts**

---

## ✨ Key Contributions

- **Consensus-based multi-level labeling pipeline**  
  Combines five unsupervised detectors to derive reliable labels from raw BGP UPDATE streams.

- **Protocol-aware synthetic data evaluation**  
  A 16-metric fidelity framework capturing:
  - Univariate and multivariate distributions
  - Correlation structure
  - Effect sizes
  - PCA geometry preservation

- **Comprehensive generator benchmark**  
  Comparison of rule-based, statistical, oversampling, hybrid, and deep generative models.

- **Cross-collector generalization analysis**  
  Evaluation across different RIPE RIS collectors and unseen incidents.

---
