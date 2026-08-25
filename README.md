# BlackScan - Complete Network & Web Vulnerability Scanner

## Description

**BlackScan** est un scanner de sécurité complet qui combine **l'analyse réseau**, **le crawling web**, **l'OSINT**, et la **détection de vulnérabilités** en un seul outil. Il est conçu pour les audits de sécurité professionnels et les tests d'intrusion éthiques.

### Fonctionnalités principales

- ** Scan réseau avancé**
  - Découverte d'hôtes (ping sweep)
  - Scan de ports (1-65535)
  - Détection de services et bannières
  - Identification OS via TTL

- ** Crawling & Scraping Web**
  - Exploration automatique des sites (jusqu'à 5 niveaux)
  - Extraction de toutes les URLs, liens, scripts, CSS
  - Détection de formulaires et paramètres
  - Analyse des commentaires HTML

- ** OSINT (Open Source Intelligence)**
  - Extraction d'emails
  - Récupération de numéros de téléphone
  - Identification du personnel
  - WHOIS et DNS records
  - Analyse des métadonnées

- ** Détection de vulnérabilités**
  - XSS (Cross-Site Scripting)
  - SQL Injection (basique)
  - Directory Listing
  - Panneaux d'administration
  - Fichiers de backup exposés
  - Headers de sécurité manquants
  - Technologies et frameworks

- ** Rapports complets**
  - Export JSON
  - Résumé détaillé
  - Statistiques en temps réel

##  Installation

### Prérequis

```bash
# Python 3.8 ou supérieur
python3 --version

# Git
git --version
