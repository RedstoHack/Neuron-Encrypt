import os
import sys
import shutil
import glob
import subprocess
import requests

GITLAB_REPO_URL = "https://gitlab.com/theredhacker0345/neuron-encrypt.git"
GITLAB_API_URL = "https://gitlab.com/api/v4/projects/theredhacker0345%2Fneuron-encrypt/releases"

def run_cmd(cmd, check=True):
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Command failed: {result.stderr}")
    return result.stdout.strip()

def ignore_readme(src, names):
    """Функция для shutil.copytree, чтобы игнорировать любые файлы README"""
    ignored = []
    for name in names:
        if name.startswith('README'):
            ignored.append(name)
    return ignored

def main():
    github_repo = os.environ.get('GITHUB_REPOSITORY')
    github_token = os.environ.get('GITHUB_TOKEN')
    
    if not github_repo or not github_token:
        print("Missing GITHUB_REPOSITORY or GITHUB_TOKEN")
        sys.exit(1)

    # Добавляем GitLab как remote и забираем ВСЕ (все коммиты, ветки, теги)
    run_cmd(['git', 'remote', 'add', 'gitlab', GITLAB_REPO_URL], check=False)
    run_cmd(['git', 'fetch', 'gitlab', '--tags', '--force'], check=False)
    run_cmd(['git', 'fetch', 'gitlab', '+refs/heads/*:refs/remotes/gitlab/*'], check=False)

    # Пушим все ветки из GitLab в GitHub
    branches_raw = run_cmd(['git', 'for-each-ref', '--format=%(refname:short)', 'refs/remotes/gitlab/'])
    if branches_raw:
        for branch in branches_raw.split('\n'):
            branch = branch.strip()
            # Игнорируем пустые строки и ссылки, не начинающиеся с 'gitlab/'
            if not branch or 'gitlab/' not in branch:
                continue
            
            local_name = branch.split('gitlab/', 1)[1]
            # Не пушим main, master и HEAD, чтобы не затереть текущую рабочую ветку и не словить ошибку
            if local_name and local_name != 'HEAD' and local_name != 'main' and local_name != 'master':
                run_cmd(['git', 'push', 'origin', f'refs/remotes/{branch}:refs/heads/{local_name}', '--force'], check=False)
                
    # Пушим все теги (для создания релизов они должны существовать в GitHub)
    run_cmd(['git', 'push', 'origin', '--tags', '--force'], check=False)

    # Определяем текущую ветку по умолчанию
    current_branch = run_cmd(['git', 'rev-parse', '--abbrev-ref', 'HEAD'])
    if current_branch == 'HEAD' or not current_branch:
        current_branch = 'main'
        
    # Проверяем, есть ли эта ветка в GitLab, если нет - пробуем master
    if not run_cmd(['git', 'rev-parse', '--verify', f'gitlab/{current_branch}'], check=False):
        if run_cmd(['git', 'rev-parse', '--verify', 'gitlab/master'], check=False):
            current_branch = 'master'
        else:
            print(f"Warning: Branch '{current_branch}' not found in GitLab. Skipping file sync.")
            current_branch = None
            
    if current_branch:
        run_cmd(['git', 'checkout', current_branch], check=False)
        
        # --- Синхронизация файлов ---
        temp_dir = 'temp_gitlab_extract'
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir, exist_ok=True)
        
        # Извлекаем файлы из ветки GitLab во временную папку
        run_cmd(['git', 'archive', f'gitlab/{current_branch}', '--output=temp.tar'], check=False)
        if not os.path.exists('temp.tar') or os.path.getsize('temp.tar') == 0:
            print(f"Failed to extract gitlab/{current_branch}. Aborting file sync.")
            shutil.rmtree(temp_dir)
            if os.path.exists('temp.tar'): os.remove('temp.tar')
        else:
            run_cmd(['tar', '-xf', 'temp.tar', '-C', temp_dir], check=False)
            os.remove('temp.tar')
            
            # 1. Бэкап README (если он есть)
            readme_files = glob.glob("README*")
            readme_backup = {}
            for rf in readme_files:
                with open(rf, 'rb') as f:
                    readme_backup[rf] = f.read()
                    
            # 2. Очистка рабочей директории (защищаем .git, sync.py, .github и README)
            for item in os.listdir('.'):
                if item in ['.git', temp_dir, 'sync.py', '.github'] or item in readme_files:
                    continue
                path = os.path.join('.', item)
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                    
            # 3. Копирование файлов из GitLab
            for item in os.listdir(temp_dir):
                if item == '.git': continue
                src = os.path.join(temp_dir, item)
                dst = os.path.join('.', item)
                
                if os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True, ignore=ignore_readme)
                else:
                    if not item.startswith('README'):
                        shutil.copy2(src, dst)
                        
            # 4. Восстановление README
            for rf, content in readme_backup.items():
                with open(rf, 'wb') as f:
                    f.write(content)
                    
            shutil.rmtree(temp_dir)
            
            # 5. Коммит и пуш изменений
            run_cmd(['git', 'config', 'user.name', 'github-actions[bot]'])
            run_cmd(['git', 'config', 'user.email', 'github-actions[bot]@users.noreply.github.com'])
            run_cmd(['git', 'add', '-A'])
            
            status = run_cmd(['git', 'status', '--porcelain'])
            if status:
                run_cmd(['git', 'commit', '-m', 'Sync files from GitLab (excluding README)'])
                run_cmd(['git', 'push', 'origin', f'HEAD:{current_branch}'])
            else:
                print("No file changes to commit.")

    # --- Синхронизация релизов ---
    print("Syncing releases...")
    try:
        gl_resp = requests.get(GITLAB_API_URL)
        gl_releases = gl_resp.json()
    except Exception as e:
        print(f"Failed to fetch GitLab releases: {e}")
        gl_releases = []
    
    gh_headers = {'Authorization': f'token {github_token}', 'Accept': 'application/vnd.github+json'}
    gh_releases_url = f"https://api.github.com/repos/{github_repo}/releases"
    
    try:
        gh_resp = requests.get(gh_releases_url, headers=gh_headers)
        gh_releases = gh_resp.json()
        if not isinstance(gh_releases, list): gh_releases = []
    except Exception as e:
        print(f"Failed to fetch GitHub releases: {e}")
        gh_releases = []
    
    gh_existing_tags = {r['tag_name'] for r in gh_releases}
    
    for gl_rel in gl_releases:
        tag = gl_rel['tag_name']
        if tag in gh_existing_tags:
            print(f"Release {tag} already exists in GitHub.")
            continue
            
        create_data = {
            "tag_name": tag,
            "name": gl_rel.get('name', tag),
            "body": gl_rel.get('description', ''),
            "draft": False,
            "prerelease": gl_rel.get('upcoming_release', False)
        }
        
        create_resp = requests.post(gh_releases_url, headers=gh_headers, json=create_data)
        if create_resp.status_code in (200, 201):
            gh_rel = create_resp.json()
            upload_url = gh_rel['upload_url'].split('{')[0]
            
            # Скачиваем и загружаем прикрепленные бинарные файлы (assets)
            assets = gl_rel.get('assets', {}).get('links', [])
            for asset in assets:
                asset_name = asset.get('name')
                asset_url = asset.get('direct_asset_url') or asset.get('url')
                if not asset_url or not asset_name: continue
                    
                print(f"Downloading asset {asset_name}...")
                try:
                    asset_resp = requests.get(asset_url, stream=True)
                    if asset_resp.status_code == 200:
                        upload_params = {'name': asset_name}
                        upload_headers = gh_headers.copy()
                        upload_headers['Content-Type'] = asset_resp.headers.get('Content-Type', 'application/octet-stream')
                        
                        print(f"Uploading asset {asset_name} to GitHub...")
                        upload_resp = requests.post(
                            upload_url, 
                            headers=upload_headers, 
                            params=upload_params, 
                            data=asset_resp.content
                        )
                        if upload_resp.status_code not in (200, 201):
                            print(f"Failed to upload {asset_name}: {upload_resp.text}")
                    else:
                        print(f"Failed to download {asset_name}: {asset_resp.status_code}")
                except Exception as e:
                    print(f"Error processing asset {asset_name}: {e}")
        else:
            print(f"Failed to create release {tag}: {create_resp.text}")

if __name__ == '__main__':
    main()
