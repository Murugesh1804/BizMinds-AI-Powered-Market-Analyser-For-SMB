from fastapi import HTTPException
import os
import tempfile
import subprocess
import shutil

def translate_text(text, source_lang="en", target_lang="hi"):
    """//Translate text using indic-trans library"""
    # Only proceed if source and target are different
    if source_lang == target_lang:
        return text
    
    # Check if languages are supported
    supported_langs = ["en", "hi", "ta", "te", "ml", "bn", "gu", "pa", "mr", "or", "kn"]
    if source_lang not in supported_langs or target_lang not in supported_langs:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported language. Supported languages: {', '.join(supported_langs)}"
        )
    
    # Create temp files for input and output
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as input_file:
        input_file.write(text)
        input_file_path = input_file.name
    
    output_file_path = input_file_path + ".out"
    
    try:
        # Run indic-trans CLI command
        cmd = [
            "indic_translate", 
            "--input", input_file_path,
            "--output", output_file_path,
            "--source", source_lang,
            "--target", target_lang
        ]
        
        process = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True
        )
        
        # Read output file
        with open(output_file_path, 'r', encoding='utf-8') as f:
            translated_text = f.read()
        
        return translated_text
    
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Translation error: {e.stderr}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Translation error: {str(e)}"
        )
    finally:
        # Clean up temp files
        if os.path.exists(input_file_path):
            os.unlink(input_file_path)
        if os.path.exists(output_file_path):
            os.unlink(output_file_path)
