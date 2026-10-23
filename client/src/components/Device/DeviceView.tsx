import { useMediaQuery } from '@librechat/client';
import OpenSidebar from '~/components/Chat/Menus/OpenSidebar';
import DevicePanel from './DevicePanel';

/**
 * Route shell for the "My Computer" panel: full-height column with the mobile sidebar
 * affordance, matching the other route-level views (`SkillsView`, `PromptsView`).
 *
 * Reachable at `/device`. The panel itself does no routing and holds no authority.
 */
export default function DeviceView() {
  const isSmallScreen = useMediaQuery('(max-width: 768px)');

  return (
    <div className="flex h-full w-full flex-col overflow-y-auto bg-presentation">
      {isSmallScreen ? (
        <div className="flex shrink-0 items-center px-4 pt-3">
          <OpenSidebar />
        </div>
      ) : null}
      <DevicePanel />
    </div>
  );
}
