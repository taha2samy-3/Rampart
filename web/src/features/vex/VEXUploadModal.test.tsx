import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';
import { VEXUploadModal } from './VEXUploadModal';

describe('VEXUploadModal', () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });

  const renderModal = (open = true) => {
    return render(
      <QueryClientProvider client={queryClient}>
        <VEXUploadModal
          open={open}
          onOpenChange={vi.fn()}
          applicationId="01931f6a-0000-7000-8000-000000000001"
          applicationName="Shop Service"
        />
      </QueryClientProvider>
    );
  };

  it('renders the modal title and file dropzone when open', () => {
    renderModal(true);

    expect(screen.getByText('Apply VEX Document')).toBeInTheDocument();
    expect(screen.getByText(/Shop Service/i)).toBeInTheDocument();
    expect(screen.getByText('Choose a VEX document or drop it here')).toBeInTheDocument();
    expect(
      screen.getByText(/Supports OpenVEX, CycloneDX VEX \/ VDR, and CSAF 2.0/i)
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Confirm & Apply' })).toBeDisabled();
  });

  it('does not render dialog content when closed', () => {
    renderModal(false);

    expect(screen.queryByText('Apply VEX Document')).toBeNull();
  });
});
