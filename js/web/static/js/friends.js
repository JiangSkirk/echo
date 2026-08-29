/* Friends v1 panel. Hidden unless /api/friends/status is enabled. */

export async function loadFriends() {
  const panel = document.getElementById('friends-panel');
  const warning = document.getElementById('friends-warning');
  if (!panel) return;
  try {
    const status = await fetch('/api/friends/status');
    if (status.status === 404) {
      panel.textContent = 'Friends 默认关闭。';
      return;
    }
    if (!status.ok) throw new Error('HTTP ' + status.status);
    const info = await status.json();
    if (warning) warning.classList.toggle('hidden', !info.warn_native);
    const list = await fetch('/api/friends');
    const data = list.ok ? await list.json() : { friends: [] };
    const friends = data.friends || [];
    panel.textContent = friends.length
      ? friends.map((item) => `${item.display_name} (${item.status})`).join('\n')
      : '还没有朋友。用邀请卡互认。';
  } catch (error) {
    panel.textContent = '无法加载 Friends。';
  }
}
