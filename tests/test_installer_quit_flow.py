"""安装/卸载前关掉 PYAS 的交互契约(静态检查 PYAS_Inno.iss)。

2026-10-19 用户要求:自动关闭 PYAS 失败时,先提示用户从托盘退出并给「重试」按钮;
用户退出后仍失败 → 再重试并确认进程是否已退出;三次仍不行 → 提示重启。

装不了是小事,把「点重试也没用、只能重启」藏起来、直接报一句 QuitFailed 才是问题,
所以这几条要钉住。
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ISS = (ROOT / 'PYAS_Inno.iss').read_text(encoding='utf-8')

LANGUAGES = [
    'english', 'chinesesimplified', 'chinesetraditional', 'japanese', 'korean',
    'french', 'spanish', 'hindi', 'arabic', 'russian', 'slovenian',
]


class QuitFlowContractTests(unittest.TestCase):
    def test_retry_and_restart_messages_exist_in_every_language(self):
        for lang in LANGUAGES:
            with self.subTest(language=lang):
                self.assertRegex(ISS, r'(?m)^%s\.QuitRetry=.+$' % lang)
                self.assertRegex(ISS, r'(?m)^%s\.QuitRestart=.+$' % lang)

    def test_retry_message_tells_the_user_to_exit_from_the_tray(self):
        line = next(l for l in ISS.splitlines() if l.startswith('chinesesimplified.QuitRetry='))
        self.assertIn('托盘', line)
        self.assertIn('重试', line)

    def test_installer_asks_before_giving_up(self):
        body = ISS[ISS.index('function EnsureOldInstanceStopped'):ISS.index('function InitializeSetup')]
        self.assertIn('MB_RETRYCANCEL', body, '必须给「重试/取消」,而不是一句错误就退出')
        self.assertIn('IDRETRY', body)
        self.assertIn('for Attempt := 1 to 3 do', body)
        self.assertLess(body.index('QuitRetry'), body.index('QuitRestart'),
                        '先让用户退出并重试,仍然失败才提示重启')

    def test_process_state_decides_success_not_the_window(self):
        """托盘常驻时没有主窗口;只看窗口会误判为「已退出」。"""
        self.assertIn('ProcessImageRunning', ISS)
        self.assertIn('tasklist', ISS)
        # 顶部有前置声明,按「签名 + var」定位真正的定义,避免切到声明行
        quit_body = ISS[ISS.index('function QuitOldInstance'):ISS.index(
            'function EnsureOldInstanceStopped(InstallPath: string): Boolean;\nvar')]
        self.assertIn('ProcessImageRunning', quit_body)
        self.assertIn('WaitForProcessExit', quit_body)

    def test_pending_alert_is_waited_out_before_shutdown(self):
        """有未决告警时先等用户处理,不要直接杀进程 —— 那次拦截会没有结论。"""
        self.assertIn('CheckForMutexes(\'PYAS.PendingAlert\')', ISS)
        self.assertIn('CreateOutputProgressPage', ISS, '等待要显示在向导里,不是模态框')
        self.assertIn('PendingAlertWait', ISS, '倒计时要作为界面文案出现')
        body = ISS[ISS.index('function EnsureOldInstanceStopped(InstallPath: string): Boolean;\nvar'):
                   ISS.index('function InitializeSetup')]
        self.assertNotIn('WaitForPendingAlert', body, '初始化阶段没有向导,不能在这里等')

    def test_manual_exit_is_accepted_without_waiting_for_a_timeout(self):
        body = ISS[ISS.index('function EnsureOldInstanceStopped'):ISS.index('function InitializeSetup')]
        self.assertIn('PYAS exited after the manual prompt', body)

    def test_setup_and_uninstall_both_use_the_guarded_path(self):
        init = ISS[ISS.index('function InitializeSetup'):ISS.index('function InitializeUninstall')]
        self.assertIn('EnsureOldInstanceStopped(OldInstallPath)', init)
        uninstall = ISS[ISS.index('function InitializeUninstall'):]
        self.assertIn('EnsureOldInstanceStopped', uninstall)


if __name__ == '__main__':
    unittest.main()
