"""Build the static native launcher and smoke-test the actual frozen executable."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import build_menu

ROOT=Path(__file__).resolve().parent
STAGE=ROOT/'Output'/'Bootstrap'
TARGET=ROOT/'Payload'/'PYAS_Launcher.exe'


def compile_launcher():
    cl,msvc=build_menu.find_msvc()
    _,_,include,lib=build_menu.find_sdk_tools()
    STAGE.mkdir(parents=True,exist_ok=True);TARGET.parent.mkdir(parents=True,exist_ok=True)
    command=[str(cl),'/nologo','/O2','/W3','/EHsc','/MT','/std:c++17','/utf-8','/DUNICODE','/D_UNICODE',
        '/I'+str(include/'um'),'/I'+str(include/'shared'),'/I'+str(include/'ucrt'),'/I'+str(msvc/'include'),
        str(ROOT/'Plugins'/'Bootstrap'/'PYAS_Launcher.cpp'),'/Fe:'+str(TARGET),'/Fo:'+str(STAGE/'PYAS_Launcher.obj'),
        'user32.lib','shell32.lib','advapi32.lib','/link','/LIBPATH:'+str(msvc/'lib'/'x64'),'/LIBPATH:'+str(lib/'um'/'x64'),
        '/LIBPATH:'+str(lib/'ucrt'/'x64'),'/SUBSYSTEM:WINDOWS','/ENTRY:wWinMainCRTStartup']
    result=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace')
    if result.returncode or not TARGET.is_file():
        raise RuntimeError('Native launcher compilation failed: '+result.stdout[-4000:]+result.stderr[-2000:])
    return TARGET


def pyas_running():
    """A running PYAS suspends the launcher this smoke test starts.

    That is process protection doing its job on an unsigned build artifact, not a
    bootstrap failure; reporting it as one sends people chasing the wrong bug.
    """
    result = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq PYAS.exe', '/NH'],
                            capture_output=True, text=True, errors='replace')
    return 'PYAS.exe' in result.stdout


def smoke_launch(launcher):
    if pyas_running():
        print('[启动检查] SKIP: PYAS 正在运行，其进程防护会暂停本测试拉起的 launcher')
        return
    executable=launcher.parent/'PYAS.exe'
    if not executable.is_file(): raise RuntimeError('Frozen PYAS.exe is missing')
    with tempfile.TemporaryDirectory(prefix='PYAS bootstrap smoke ') as directory:
        for inherited in (False,True):
            env=os.environ.copy()
            env.pop('PYINSTALLER_RESET_ENVIRONMENT',None)
            if inherited:
                env.update({'_PYI_ARCHIVE_FILE':str(executable.resolve()),
                    '_PYI_APPLICATION_HOME_DIR':str(Path(directory)/'_MEI-already-removed'),
                    '_PYI_PARENT_PROCESS_LEVEL':'1'})
            else:
                for name in tuple(env):
                    if name.startswith('_PYI_'): env.pop(name)
            process=subprocess.Popen([str(launcher),'--pyas-bootstrap-probe'],cwd=str(launcher.parent),env=env,
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try: stdout,stderr=process.communicate(timeout=40)
            except subprocess.TimeoutExpired:
                # The native launcher's kill-on-close job owns the entire tree.
                process.kill();process.communicate()
                raise RuntimeError('Frozen bootstrap probe timed out')
            if process.returncode:
                raise RuntimeError('Frozen bootstrap probe failed: '+str(process.returncode))
            print('[启动检查] '+('stale onefile environment' if inherited else 'clean environment')+' OK')


if __name__=='__main__':
    smoke_launch(compile_launcher())
