import PyPDF2
import re
import io
import numpy as np

def extract_pdf_features(pdf_bytes):
    
    
    pdf_stream = io.BytesIO(pdf_bytes)
    
    pdf_reader = PyPDF2.PdfReader(pdf_stream)
    features = {
        'pdfsize': 0,
        'pages': 0,
        'title characters': 0,
        'images': 0,
        'obj': 0,
        'endobj': 0,
        'stream': 0,
        'endstream': 0,
        'xref': 0,
        'trailer': 0,
        'startxref': 0,
        'ObjStm': 0,
        'JS': 0,
        'OBS_JS': 0,
        'Javascript': 0,
        'OBS_Javascript': 0,
        'OpenAction': 0,
        'OBS_OpenAction': 0,
        'Acroform': 0,
        'OBS_Acroform': 0
    }


    # features['pdfsize'] = round(len(pdf_bytes) / 1048576, 3)
    features['pdfsize'] = round(len(pdf_bytes) / 1000000, 3)

    features['pages'] = len(pdf_reader.pages) 

    
    if pdf_reader.metadata:
        title = pdf_reader.metadata.title
  
        features['title characters'] = len(title) if title else 0

    # Extracting the number of images in the PDF
    for page in pdf_reader.pages:
        features['images'] += len(page.images)
  
    # pdf_content = pdf_bytes.decode('ascii', errors='ignore')
    keywords = [b'obj', b'endobj', b'stream', b'endstream', b'trailer', b'startxref', b'xref', b'/ObjStm', b'/JS', b'/JavaScript', b'/OpenAction', b'/AcroForm']

    for keyword in keywords:
        if keyword[0] == 47:
            pattern = re.escape(keyword)
            if keyword == b'/ObjStm':
                feature = "ObjStm"
            if keyword == b'/JS':
                feature = "JS"
            if keyword == b'/JavaScript':
                feature = "Javascript"
            if keyword == b'/OpenAction':
                feature = "OpenAction"
            if keyword == b'/AcroForm':
                feature = "Acroform"
        
        else:
            
            feature = keyword.decode('utf-8')
  
            if keyword == b'obj':
            # pattern = rb'(\d+\s+\d+\s+obj\s*)' #+ rb'(?!endobj)'  # Negative lookahead to exclude "endobj"
                pattern = rb'\bobj\b'
            if keyword == b'stream':
                pattern = rb'\bstream\b' #+ rb'(?!endstream)'
            else:
                pattern = re.escape(keyword)
     
        features[feature] = len(re.findall(pattern, pdf_bytes)) 
        
    features['xref'] = features['xref'] - features['startxref']  
    features['obj'] = features['obj'] - features['endobj']  

    # Convert features dictionary to a NumPy array
    feature_values = list(features.values())
    feature_array = np.array(feature_values).reshape(1, -1)
    
    # return feature_arra
   
    return feature_array



