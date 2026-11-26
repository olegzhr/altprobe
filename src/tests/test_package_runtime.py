#!/usr/bin/env python3
"""Verify the DEB in an isolated dpkg root; never install on the host."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

CONFIGS=['altprobe.yaml','api_guard.yaml','scoring_weights.yaml','sbom.yaml']

def run(*args,**kwargs):
    return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,**kwargs)

def main():
    package=Path(sys.argv[1]).resolve()
    repo=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='package-p1-',dir=package.parent) as directory:
        folder=Path(directory)
        stage=folder/'stage'
        run('dpkg-deb','--raw-extract',str(package),str(stage))
        conffiles=(stage/'DEBIAN/conffiles').read_text().splitlines()
        assert all('/etc/altprobe/'+name in conffiles for name in CONFIGS)
        # Strip maintainer scripts ONLY from the disposable fixture, so no
        # absolute-path postinst can touch the host while testing dpkg behavior.
        for name in ['preinst','postinst','prerm','postrm','triggers']:
            (stage/'DEBIAN'/name).unlink(missing_ok=True)
        old=folder/'old.deb'; new=folder/'new.deb'
        run('dpkg-deb','--build',str(stage),str(old))
        for name in CONFIGS:
            with (stage/'etc/altprobe'/name).open('a') as stream: stream.write('\n# changed package default\n')
        run('dpkg-deb','--build',str(stage),str(new))
        for legacy in [False,True]:
            first=old
            if legacy:
                (stage/'DEBIAN/conffiles').unlink()
                first=folder/'legacy.deb'
                run('dpkg-deb','--build',str(stage),str(first))
            root=folder/('legacy-root' if legacy else 'root')
            admin=root/'var/lib/dpkg'; admin.mkdir(parents=True)
            (admin/'status').touch()
            def install(deb):
                run('dpkg','--root='+str(root),'--log='+str(folder/'dpkg.log'),
                    '--force-not-root','--force-confold','--force-depends','--install',str(deb))
            install(first)
            expected={name:'local-setting-'+name+'\n' for name in CONFIGS}
            for name,content in expected.items(): (root/'etc/altprobe'/name).write_text(content)
            install(new) # same version 1.0.2; modified package payload
            for name,content in expected.items(): assert (root/'etc/altprobe'/name).read_text()==content,name
            print('PASS DEB preserves all four local YAMLs: '+('migration from legacy package' if legacy else 'same-version reinstall'))
        binary=folder/'bin'; binary.mkdir()
        log=folder/'start.log'
        (binary/'altprobe').write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$P1_START_LOG"\nexit 7\n')
        (binary/'redis-cli').write_text('#!/bin/sh\necho DESTRUCTIVE >> "$P1_START_LOG"\nexit 99\n')
        for path in binary.iterdir(): path.chmod(0o755)
        result=subprocess.run(['bash',str(repo/'scripts/altprobe-start.sh')],
            env=dict(os.environ,PATH=str(binary)+':/usr/bin:/bin',P1_START_LOG=str(log)))
        assert result.returncode==7 and log.read_text()=='start\n'
        print('PASS start wrapper preserves Redis and propagates collector exit status')

if __name__=='__main__': main()
