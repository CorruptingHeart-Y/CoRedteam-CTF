import chromadb
import os
import textwrap

DB_PATH = './co_redteam_memory'


def show_all_memory():
    client = chromadb.PersistentClient(path=DB_PATH)
    collections = client.list_collections()

    if not collections:
        print('[EMPTY] No collections found in', DB_PATH)
        return

    total = 0
    for col in collections:
        count = col.count()
        if count == 0:
            print(f'\n{"=" * 70}')
            print(f'  Collection: {col.name}   (empty)')
            print(f'{"=" * 70}')
            continue

        result = col.get(include=['documents', 'metadatas'])
        docs = result['documents']
        ids = result.get('ids', [])
        metas = result.get('metadatas') or [{}] * len(docs)

        print(f'\n{"=" * 70}')
        print(f'  Collection: {col.name}   ({count} records)')
        print(f'{"=" * 70}')

        for i, (doc, mid, meta) in enumerate(zip(docs, ids, metas)):
            total += 1
            meta_str = ', '.join(f'{k}={v}' for k, v in meta.items()) if meta else ''
            header = f'  --- [{i+1}/{count}] ID: {mid}'
            if meta_str:
                header += f' | {meta_str}'
            print(header)

            wrapped = textwrap.fill(doc, width=66, initial_indent='    ', subsequent_indent='    ')
            print(wrapped)
            print()

    print(f'{'=' * 70}')
    print(f'  TOTAL: {total} records across {len(collections)} collections')
    print(f'  Path : {os.path.abspath(DB_PATH)}')
    print(f"{'=' * 70}")

    b_path = './b/co_redteam_memory'
    if os.path.exists(b_path):
        print(f'\n[WARN] Legacy DB exists at: {b_path}')
    else:
        print('\n[OK] Stage 2 correctly points to root DB')


if __name__ == '__main__':
    show_all_memory()