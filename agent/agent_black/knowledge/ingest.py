#!/usr/bin/env python3
"""
Agent BLACK Knowledge Ingestion

Ingest PDFs and documents into the vector database for RAG.
This gives Agent BLACK the ability to learn from security books,
guides, and your own notes.

Usage:
    python ingest.py                    # Ingest from pdfs/ folder
    python ingest.py --pdf-dir /path    # Ingest from custom folder  
    python ingest.py --force            # Re-ingest everything

Requirements:
    pip install langchain langchain-community chromadb pymupdf ollama rich
"""

import sys
import argparse
from pathlib import Path
from typing import List, Tuple

try:
    import fitz
    from langchain.text_splitter import RecursiveCharacterTextSplitter
    from langchain_community.embeddings import OllamaEmbeddings
    from langchain_community.vectorstores import Chroma
    HAS_DEPS = True
except ImportError as e:
    HAS_DEPS = False
    MISSING_DEP = str(e)

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn
    console = Console()
except ImportError:
    class Console:
        def print(self, *args, **kwargs):
            text = args[0] if args else ""
            text = str(text).replace("[bold cyan]", "").replace("[/bold cyan]", "")
            text = text.replace("[green]", "").replace("[/green]", "")
            text = text.replace("[red]", "").replace("[/red]", "")
            text = text.replace("[yellow]", "").replace("[/yellow]", "")
            text = text.replace("[dim]", "").replace("[/dim]", "")
            text = text.replace("[bold]", "").replace("[/bold]", "")
            print(text)
    console = Console()
    Progress = None


KNOWLEDGE_DIR = Path(__file__).parent
PDF_DIR = KNOWLEDGE_DIR / "pdfs"
DB_DIR = KNOWLEDGE_DIR / "vector_db"

EMBED_MODEL = "nomic-embed-text"
OLLAMA_URL = "http://localhost:11434"
CHUNK_SIZE = 500
CHUNK_OVERLAP = 50


def extract_text_from_pdf(pdf_path: Path) -> str:
    try:
        doc = fitz.open(pdf_path)
        text = ""
        for page in doc:
            text += page.get_text()
        doc.close()
        return text
    except Exception as e:
        console.print(f"[red]Error reading {pdf_path.name}: {e}[/red]")
        return ""


def get_all_documents(folder: Path) -> List[Tuple[Path, str]]:
    documents = []
    extensions = [".pdf", ".txt", ".md"]
    
    for ext in extensions:
        for file_path in folder.rglob(f"*{ext}"):
            if ext == ".pdf":
                text = extract_text_from_pdf(file_path)
            else:
                try:
                    text = file_path.read_text(encoding="utf-8", errors="ignore")
                except Exception as e:
                    console.print(f"[red]Error reading {file_path.name}: {e}[/red]")
                    continue
            
            if text.strip():
                documents.append((file_path, text))
    
    return documents


def main():
    parser = argparse.ArgumentParser(description="Ingest documents into Agent BLACK's knowledge base")
    parser.add_argument("--pdf-dir", type=str, help="Custom PDF directory")
    parser.add_argument("--force", action="store_true", help="Force re-ingestion, delete existing DB")
    parser.add_argument("--ollama-url", type=str, default=OLLAMA_URL, help="Ollama server URL")
    args = parser.parse_args()
    
    if not HAS_DEPS:
        console.print(f"[red]Missing dependency: {MISSING_DEP}[/red]")
        console.print("\nInstall with:")
        console.print("  pip install langchain langchain-community chromadb pymupdf ollama rich")
        sys.exit(1)
    
    console.print("\n[bold cyan]Agent BLACK Knowledge Ingestion[/bold cyan]\n")
    
    pdf_folder = Path(args.pdf_dir) if args.pdf_dir else PDF_DIR
    
    if not pdf_folder.exists():
        console.print(f"[red]PDF folder not found: {pdf_folder}[/red]")
        console.print("\nCreate the folder and add your PDFs:")
        console.print(f"  mkdir {pdf_folder}")
        console.print(f"  # Add PDFs to {pdf_folder}")
        sys.exit(1)
    
    if args.force and DB_DIR.exists():
        import shutil
        shutil.rmtree(DB_DIR)
        console.print("[yellow]Deleted existing database[/yellow]")
    
    console.print(f"[dim]PDF folder: {pdf_folder}[/dim]")
    console.print(f"[dim]Database: {DB_DIR}[/dim]")
    console.print(f"[dim]Ollama: {args.ollama_url}[/dim]\n")
    
    console.print("Finding documents...")
    documents = get_all_documents(pdf_folder)
    
    if not documents:
        console.print("[red]No documents found![/red]")
        console.print(f"\nAdd PDFs, TXT, or MD files to: {pdf_folder}")
        sys.exit(1)
    
    console.print(f"[green]Found {len(documents)} documents[/green]\n")
    
    for doc_path, _ in documents:
        rel_path = doc_path.relative_to(pdf_folder) if pdf_folder in doc_path.parents else doc_path.name
        console.print(f"  {rel_path}")
    
    console.print()
    
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        length_function=len,
    )
    
    all_chunks = []
    all_metadatas = []
    
    for doc_path, text in documents:
        console.print(f"Chunking {doc_path.name}...")
        chunks = splitter.split_text(text)
        
        for i, chunk in enumerate(chunks):
            all_chunks.append(chunk)
            all_metadatas.append({
                "source": doc_path.name,
                "chunk": i,
                "path": str(doc_path),
            })
        
        console.print(f"  {doc_path.name}: {len(chunks)} chunks")
    
    console.print(f"\n[bold]Total chunks: {len(all_chunks)}[/bold]\n")
    console.print("[cyan]Creating embeddings (this may take a while)...[/cyan]")
    
    embeddings = OllamaEmbeddings(
        model=EMBED_MODEL,
        base_url=args.ollama_url
    )
    
    console.print("Embedding and storing...")
    
    vectordb = Chroma.from_texts(
        texts=all_chunks,
        embedding=embeddings,
        metadatas=all_metadatas,
        persist_directory=str(DB_DIR)
    )
    
    console.print(f"\n[bold green]Success![/bold green]")
    console.print(f"Stored {len(all_chunks)} chunks in {DB_DIR}")
    console.print("\nAgent BLACK can now use this knowledge for RAG queries.")


if __name__ == "__main__":
    main()
