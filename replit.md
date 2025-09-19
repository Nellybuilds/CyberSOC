# replit.md

## Overview

This is a cybersecurity incident response playbook assistant - a web-based operational tool designed to guide cybersecurity analysts through real incident response procedures. The application serves as a comprehensive incident response assistant, featuring an interactive workflow system, role-based views for different stakeholders (Analyst, Manager, Client), and comprehensive logging and reporting capabilities.

The system provides a realistic cybersecurity incident management environment with live alerts, endpoint data, security logs, and AI-guided response workflows that follow industry-standard incident response procedures including MITRE ATT&CK framework integration.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **React with TypeScript**: Modern SPA built with React 18, using TypeScript for type safety
- **Component Library**: Radix UI components with shadcn/ui design system for consistent, accessible UI components
- **Styling**: Tailwind CSS with custom cybersecurity theme colors and dark mode support
- **State Management**: TanStack Query (React Query) for server state management and caching
- **Routing**: Wouter for lightweight client-side routing
- **Form Handling**: React Hook Form with Zod validation for type-safe form management

### Backend Architecture  
- **Express.js Server**: RESTful API server with TypeScript support
- **File-based Storage**: JSON files for mock data storage (alerts, endpoints, logs, playbooks)
- **API Structure**: Resource-based endpoints following REST conventions (/api/alerts, /api/endpoints, etc.)
- **Development Setup**: Vite dev server integration with HMR support for full-stack development

### Data Layer
- **PostgreSQL Ready**: Drizzle ORM configured for PostgreSQL with Neon database support
- **Schema Design**: Comprehensive TypeScript schemas using Zod for alerts, endpoints, logs, playbooks, and workflow sessions
- **Mock Data**: JSON files providing realistic cybersecurity incident data for operational scenarios

### Key Features Architecture
- **Role-Based Views**: Dynamic UI adaptation based on user role (Analyst/Manager/Client)
- **Workflow Engine**: Step-by-step guided incident response using hardcoded playbook logic
- **Live Data Integration**: Security events and logs with realistic timestamps and data
- **MITRE ATT&CK Integration**: Technique mapping and visualization throughout the incident lifecycle
- **Report Generation**: Automated post-incident reporting with export capabilities

### Component Design Patterns
- **Atomic Design**: Modular component architecture with reusable UI elements
- **Data Fetching**: Custom hooks wrapping TanStack Query for consistent API interactions
- **Type Safety**: End-to-end TypeScript with shared schemas between frontend and backend
- **Accessibility**: Radix UI primitives ensuring WCAG compliance across all interactive elements

## External Dependencies

### Core Framework Dependencies
- **React 18**: Frontend framework with hooks and concurrent features
- **Express.js**: Backend web framework for Node.js
- **TypeScript**: Type system for JavaScript providing compile-time type checking
- **Vite**: Build tool and development server with fast HMR

### UI and Styling
- **Radix UI**: Unstyled, accessible UI primitives for complex components
- **Tailwind CSS**: Utility-first CSS framework for rapid UI development
- **Lucide React**: Icon library with consistent SVG icons
- **Class Variance Authority**: Utility for creating variant-based component APIs

### Data Management
- **TanStack Query**: Server state management with caching, synchronization, and error handling
- **Drizzle ORM**: TypeScript ORM for database operations with PostgreSQL support
- **Zod**: TypeScript-first schema validation library
- **Neon Database**: Serverless PostgreSQL database platform

### Development and Build Tools
- **TSX**: TypeScript execution environment for Node.js development
- **ESBuild**: Fast JavaScript bundler for production builds
- **PostCSS**: CSS processing tool with autoprefixer support
- **Wouter**: Minimalist routing library for React applications

### Form and Validation
- **React Hook Form**: Performant forms library with minimal re-renders
- **Hookform Resolvers**: Integration between React Hook Form and validation libraries

### Utility Libraries
- **Date-fns**: Modern JavaScript date utility library
- **CLSX/CN**: Utility for constructing className strings conditionally
- **Nanoid**: URL-safe unique ID generator for client-side operations