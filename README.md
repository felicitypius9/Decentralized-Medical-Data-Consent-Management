# Decentralized Medical Data Consent Management (DMDCM)

A blockchain-based solution for managing medical data consent built on Stacks blockchain, enabling secure and transparent control over healthcare information access.

## Overview

DMDCM provides a decentralized platform where patients can manage consent for their medical data, healthcare providers can request access, and all interactions are securely logged on the blockchain.

## Features

### Core Functionality
- **Consent Management**
  - Grant/revoke consent to healthcare providers
  - Time-limited consent options
  - Emergency access controls
  - Granular data category permissions

### Patient Features
- Patient registration and profile management
- Emergency contact designation
- Access history tracking
- Provider rating system

### Provider Features
- Provider registration with license verification
- Access request system
- Active/inactive status management
- Consent group management

### Security & Logging
- Comprehensive access logging
- Transparent audit trail
- Emergency override protocols
- Time-stamped activities

## Technical Architecture

### Smart Contracts
The system consists of several integrated components:
- Patient Registry
- Provider Registry
- Consent Management
- Access Logging
- Emergency Access Control

### Data Structures
- Patient Consents
- Provider Information
- Access Logs
- Emergency Contacts
- Timed Consents
- Category Permissions

## Development

### Prerequisites
- Clarinet
- Node.js v18.x
- Stacks blockchain development environment

### Installation
```bash
npm install
