import { useState, useEffect, useCallback } from 'react';
import { useRecoilValue } from 'recoil';
import { SystemRoles } from 'librechat-data-provider';
import { isError } from '~/components/Chat/Messages/Content/ToolOutput';
import { useProgress, useExpandCollapse, useAuthContext } from '~/hooks';
import store from '~/store';

interface ToolCallState {
  showCode: boolean;
  toggleCode: () => void;
  expandStyle: React.CSSProperties;
  expandRef: React.RefObject<HTMLDivElement>;
  progress: number;
  cancelled: boolean;
  hasError: boolean;
  hasOutput: boolean;
  hasContent: boolean;
}

export default function useToolCallState(
  initialProgress: number,
  isSubmitting: boolean,
  output: string,
  hasInput: boolean,
  onExpand?: () => void,
): ToolCallState {
  const autoExpand = useRecoilValue(store.autoExpandTools);
  const { user } = useAuthContext();
  const shouldAutoExpand = autoExpand && user?.role !== SystemRoles.USER;
  const hasOutput = output.length > 0;
  const hasError = hasOutput && isError(output);
  const hasContent = hasInput || hasOutput;

  const [showCode, setShowCode] = useState(() => shouldAutoExpand && hasContent);
  const { style: expandStyle, ref: expandRef } = useExpandCollapse(showCode);

  useEffect(() => {
    if (shouldAutoExpand && hasContent) {
      setShowCode(true);
    }
  }, [shouldAutoExpand, hasContent]);

  const progress = useProgress(initialProgress);
  const toggleCode = useCallback(() => {
    setShowCode((prev) => {
      const next = !prev;
      if (next) {
        onExpand?.();
      }
      return next;
    });
  }, [onExpand]);
  const cancelled = !isSubmitting && progress < 1 && !hasError;

  return {
    showCode,
    toggleCode,
    expandStyle,
    expandRef,
    progress,
    cancelled,
    hasError,
    hasOutput,
    hasContent,
  };
}
