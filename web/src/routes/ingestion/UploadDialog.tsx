import { useId, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { qk, toProblem, uploadReport } from '@/api';
import { Button, Dialog, DialogClose, DialogContent, Input, ProblemMessage, Spinner, useToast } from '@/components';
import { cn } from '@/lib/cn';

export interface UploadDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function UploadDialog({ open, onOpenChange }: UploadDialogProps) {
  const { t } = useTranslation();
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && (
        <DialogContent title={t('ingestion.uploadTitle')} description={t('ingestion.uploadDescription')} closeLabel={t('common.close')}>
          <UploadForm onDone={() => onOpenChange(false)} />
        </DialogContent>
      )}
    </Dialog>
  );
}

function UploadForm({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const toast = useToast();
  const qc = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [file, setFile] = useState<File | null>(null);
  const [app, setApp] = useState('');
  const [track, setTrack] = useState('main');
  const [isDragging, setIsDragging] = useState(false);

  const ids = {
    file: useId(),
    app: useId(),
    track: useId(),
  };

  const mutation = useMutation({
    mutationFn: () => {
      if (!file) throw new Error('No file selected');
      return uploadReport(file, {
        application: app.trim() || undefined,
        track: track.trim() || undefined,
      });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.runs.all() });
      toast.info(t('ingestion.uploadSuccess'));
      onDone();
    },
  });

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setFile(e.dataTransfer.files[0]!);
    }
  };

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (file) mutation.mutate();
      }}
      className="flex flex-col gap-4 p-4"
    >
      <div>
        <label htmlFor={ids.file} className="mb-1 block text-12 font-medium text-ink">
          {t('ingestion.uploadFileLabel')}
        </label>
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={cn(
            'flex cursor-pointer flex-col items-center justify-center rounded-ctl border-2 border-dashed p-6 text-center transition-colors',
            isDragging ? 'border-accent bg-accent/5' : 'border-rule hover:border-ink-2',
            file && 'border-solid border-rule bg-surface',
          )}
        >
          <input
            ref={fileInputRef}
            id={ids.file}
            type="file"
            className="hidden"
            accept=".json,.sarif,.xml,.spdx"
            onChange={(e) => {
              if (e.target.files && e.target.files.length > 0) {
                setFile(e.target.files[0]!);
              }
            }}
          />
          {file ? (
            <div className="flex flex-col items-center gap-1">
              <span className="font-medium text-ink">{file.name}</span>
              <span className="text-12 text-ink-2">{(file.size / 1024).toFixed(1)} KB</span>
            </div>
          ) : (
            <span className="text-13 text-ink-2">{t('ingestion.uploadDropZone')}</span>
          )}
        </div>
      </div>

      <div>
        <label htmlFor={ids.app} className="mb-1 block text-12 font-medium text-ink">
          {t('ingestion.uploadApplication')}
        </label>
        <Input
          id={ids.app}
          value={app}
          onChange={(e) => setApp(e.target.value)}
          placeholder={t('ingestion.uploadApplicationPlaceholder')}
        />
      </div>

      <div>
        <label htmlFor={ids.track} className="mb-1 block text-12 font-medium text-ink">
          {t('ingestion.uploadTrack')}
        </label>
        <Input
          id={ids.track}
          value={track}
          onChange={(e) => setTrack(e.target.value)}
          placeholder={t('ingestion.uploadTrackPlaceholder')}
        />
      </div>

      {mutation.isError && (
        <ProblemMessage problem={toProblem(mutation.error)} title={t('common.error')} />
      )}

      <div className="flex items-center justify-end gap-2 border-t border-rule pt-4">
        <DialogClose asChild>
          <Button type="button" variant="ghost">
            {t('common.cancel')}
          </Button>
        </DialogClose>
        <Button type="submit" variant="primary" disabled={!file || mutation.isPending}>
          {mutation.isPending && <Spinner size={14} />}
          {mutation.isPending ? t('ingestion.uploadUploading') : t('ingestion.uploadSubmit')}
        </Button>
      </div>
    </form>
  );
}
