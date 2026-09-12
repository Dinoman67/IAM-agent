import React from 'react';
import { ProviderCapabilities, ProviderName } from '../types';
import { ProviderCapabilitiesMatrix } from '../components/providers/ProviderCapabilitiesMatrix';
import { ArchitectureDiagram } from '../components/dashboard/ArchitectureDiagram';

interface CapabilitiesPageProps {
  providers?: Record<ProviderName, ProviderCapabilities>;
}

export const CapabilitiesPage: React.FC<CapabilitiesPageProps> = ({ providers }) => {
  return (
    <div className="space-y-5">
      <ProviderCapabilitiesMatrix providers={providers} />
      <ArchitectureDiagram />
    </div>
  );
};
