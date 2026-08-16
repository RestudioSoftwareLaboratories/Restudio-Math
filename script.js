// ========== SECURITY UTILITIES ==========

// 1. Sanitization - منع هجمات XSS
function sanitizeText(text) {
    if (text === null || text === undefined) return '';
    if (typeof text !== 'string') return String(text);
    
    var map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;',
        '=': '&#x3D;',
        '`': '&#x60;'
    };
    return text.replace(/[&<>"'/=`]/g, function(match) {
        return map[match];
    });
}

function isValidText(text) {
    if (typeof text !== 'string') return false;
    var dangerousPatterns = [
        /javascript:/i,
        /on\w+\s*=/i,
        /<script/i,
        /<iframe/i,
        /<object/i,
        /<embed/i,
        /data:text\/html/i,
        /vbscript:/i
    ];
    for (var i = 0; i < dangerousPatterns.length; i++) {
        if (dangerousPatterns[i].test(text)) return false;
    }
    return true;
}

// 2. File Validation for .remt
function validateREMTFile(content) {
    if (typeof content !== 'string') {
        throw new Error('Invalid file format: Content must be a string');
    }
    
    var MAX_FILE_SIZE_MB = 1;
    var sizeInMB = new Blob([content]).size / (1024 * 1024);
    if (sizeInMB > MAX_FILE_SIZE_MB) {
        throw new Error('File too large: ' + sizeInMB.toFixed(2) + 'MB (max ' + MAX_FILE_SIZE_MB + 'MB)');
    }
    
    var MAX_CHARS = 50000;
    if (content.length > MAX_CHARS) {
        throw new Error('File too large: ' + content.length + ' characters (max ' + MAX_CHARS + ')');
    }
    
    // التحقق من عدم وجود محتوى ضار في النص
    if (!isValidText(content)) {
        throw new Error('Suspicious content detected in file');
    }
    
    return true;
}

// 3. LaTeX Validation
function validateLatex(latex) {
    if (typeof latex !== 'string') return false;
    // منع محاولات إدخال HTML في LaTeX
    var dangerousPatterns = [
        /<script/i,
        /<iframe/i,
        /<object/i,
        /<embed/i,
        /on\w+\s*=/i,
        /javascript:/i,
        /data:text\/html/i
    ];
    for (var i = 0; i < dangerousPatterns.length; i++) {
        if (dangerousPatterns[i].test(latex)) return false;
    }
    return true;
}

// ========== MAIN APPLICATION ==========

(function() {
    'use strict';
    
    // DOM elements
    var latexInput = document.getElementById('latexInput');
    var previewBox = document.getElementById('previewBox');
    var errorMsg = document.getElementById('errorMsg');
    var charCountSpan = document.getElementById('charCount');
    var hasUnsavedChanges = false;

    // ============ UNSAVED CHANGES ============
    function markAsChanged() {
        hasUnsavedChanges = true;
    }

    function clearUnsaved() {
        hasUnsavedChanges = false;
    }

    window.addEventListener('beforeunload', function(e) {
        if (hasUnsavedChanges) {
            e.preventDefault();
            e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
            return e.returnValue;
        }
    });

    // ============ UPDATE PREVIEW ============
    function updatePreview() {
        var latex = latexInput.value;
        var sanitizedLatex = sanitizeText(latex);
        
        // التحقق من صحة النص
        if (!validateLatex(sanitizedLatex)) {
            errorMsg.textContent = 'Invalid content detected.';
            previewBox.innerHTML = '<span style="color:#e74c3c;">Invalid content</span>';
            charCountSpan.textContent = latex.length;
            return;
        }
        
        if (latex.trim() === "") {
            previewBox.innerHTML = '\\( \\displaystyle \\text{Equation will appear here...} \\)';
            errorMsg.textContent = '';
            charCountSpan.textContent = latex.length;
            return;
        }
        
        try {
            var rendered = katex.renderToString(latex, {
                throwOnError: true,
                displayMode: true,
                trust: false // منع تنفيذ أكواد ضارة
            });
            previewBox.innerHTML = rendered;
            errorMsg.textContent = '';
            markAsChanged();
        } catch (err) {
            errorMsg.textContent = 'Syntax error: ' + err.message;
            // Attempt fallback to show partial rendering
            try {
                var fallback = katex.renderToString(latex, { throwOnError: false, displayMode: true, trust: false });
                previewBox.innerHTML = fallback;
            } catch(e) {
                previewBox.innerHTML = '<span style="color:#e74c3c;">Invalid LaTeX expression</span>';
            }
        }
        charCountSpan.textContent = latex.length;
    }

    // ============ INSERT AT CURSOR ============
    function insertAtCursor(text) {
        var start = latexInput.selectionStart;
        var end = latexInput.selectionEnd;
        var value = latexInput.value;
        var sanitizedText = sanitizeText(text);
        
        if (!isValidText(sanitizedText)) {
            alert('Invalid text detected.');
            return;
        }
        
        latexInput.value = value.substring(0, start) + sanitizedText + value.substring(end);
        latexInput.focus();
        var newCursorPos = start + sanitizedText.length;
        latexInput.selectionStart = newCursorPos;
        latexInput.selectionEnd = newCursorPos;
        updatePreview();
    }

    // ============ EXPORT .REMT ============
    function exportAsRemt() {
        var content = latexInput.value;
        if (!content.trim()) {
            alert('No content to export');
            return;
        }
        
        var sanitizedContent = sanitizeText(content);
        if (!isValidText(sanitizedContent)) {
            alert('Invalid content detected.');
            return;
        }
        
        try {
            var blob = new Blob([sanitizedContent], { type: 'text/plain' });
            var a = document.createElement('a');
            var url = URL.createObjectURL(blob);
            a.href = url;
            a.download = 'equation.remt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            clearUnsaved();
        } catch (err) {
            alert('Error exporting: ' + err.message);
        }
    }

    // ============ IMPORT .REMT ============
    function importREMTFile(file) {
        var reader = new FileReader();
        reader.onload = function(ev) {
            try {
                var content = ev.target.result;
                validateREMTFile(content);
                latexInput.value = content;
                updatePreview();
                clearUnsaved();
            } catch(err) {
                alert('Import failed: ' + err.message);
            }
        };
        reader.onerror = function() {
            alert('Error reading file.');
        };
        reader.readAsText(file);
    }

    // ============ COPY LATEX ============
    function copyLatex() {
        var content = latexInput.value;
        if (!content.trim()) {
            alert('No content to copy');
            return;
        }
        
        var sanitizedContent = sanitizeText(content);
        if (!isValidText(sanitizedContent)) {
            alert('Invalid content detected.');
            return;
        }
        
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(sanitizedContent).then(function() {
                alert('LaTeX code copied to clipboard');
            }).catch(function() {
                fallbackCopy(sanitizedContent);
            });
        } else {
            fallbackCopy(sanitizedContent);
        }
    }

    function fallbackCopy(text) {
        var textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            alert('LaTeX code copied to clipboard');
        } catch (err) {
            alert('Failed to copy. Please select the text manually.');
        }
        document.body.removeChild(textarea);
    }

    // ============ KEYBOARD SHORTCUTS ============
    function setupKeyboardShortcuts() {
        document.addEventListener('keydown', function(e) {
            // Ctrl+S - Save/Export
            if (e.ctrlKey && e.key === 's') {
                e.preventDefault();
                if (latexInput.value.trim()) {
                    exportAsRemt();
                }
                return;
            }
            
            // Ctrl+O - Open
            if (e.ctrlKey && e.key === 'o') {
                e.preventDefault();
                var input = document.createElement('input');
                input.type = 'file';
                input.accept = '.remt,.json,.txt';
                input.onchange = function(ev) {
                    if (ev.target.files[0]) {
                        importREMTFile(ev.target.files[0]);
                    }
                };
                input.click();
                return;
            }
            
            // Ctrl+N - New/Clear
            if (e.ctrlKey && e.key === 'n') {
                e.preventDefault();
                if (latexInput.value.trim() && confirm('Clear current content?')) {
                    latexInput.value = '';
                    updatePreview();
                    clearUnsaved();
                } else if (!latexInput.value.trim()) {
                    latexInput.value = '';
                    updatePreview();
                    clearUnsaved();
                }
                return;
            }
            
            // Escape - Clear error
            if (e.key === 'Escape') {
                errorMsg.textContent = '';
                return;
            }
        });
    }

    // ============ EVENT LISTENERS ============
    function setupEventListeners() {
        // New button
        document.getElementById('newBtn').addEventListener('click', function() {
            if (latexInput.value.trim() && confirm('Clear current content?')) {
                latexInput.value = '';
                updatePreview();
                clearUnsaved();
            } else if (!latexInput.value.trim()) {
                latexInput.value = '';
                updatePreview();
                clearUnsaved();
            }
        });
        
        // Open button
        document.getElementById('openBtn').addEventListener('click', function() {
            var input = document.createElement('input');
            input.type = 'file';
            input.accept = '.remt,.json,.txt';
            input.onchange = function(e) {
                if (e.target.files[0]) {
                    importREMTFile(e.target.files[0]);
                }
            };
            input.click();
        });
        
        // Save/Export button
        document.getElementById('saveBtn').addEventListener('click', function() {
            exportAsRemt();
        });
        
        // Fraction button
        document.getElementById('fracBtn').addEventListener('click', function() {
            insertAtCursor('\\frac{}{}');
        });
        
        // Root button
        document.getElementById('rootBtn').addEventListener('click', function() {
            insertAtCursor('\\sqrt{}');
        });
        
        // Power button
        document.getElementById('powerBtn').addEventListener('click', function() {
            insertAtCursor('^{}');
        });
        
        // KaTeX Help button
        document.getElementById('katexBtn').addEventListener('click', function() {
            var helpText = 'KaTeX Math Editor Help\n\nYou can write any supported LaTeX:\n- Fractions: \\frac{a}{b}\n- Square roots: \\sqrt{x}\n- Exponents: x^{n}\n- Integrals: \\int_{0}^{\\infty}\n- Summations: \\sum_{i=1}^{n}\n- Greek letters: \\alpha, \\beta, \\gamma, \\pi\n- Infinity: \\infty\n\nQuadratic formula:\n\\frac{-b \\pm \\sqrt{b^2 - 4ac}}{2a}';
            alert(helpText);
            insertAtCursor('\\frac{-b \\pm \\sqrt{b^2 - 4ac}}{2a}');
        });
        
        // Symbol buttons
        var symBtns = document.querySelectorAll('.sym-btn');
        for (var i = 0; i < symBtns.length; i++) {
            symBtns[i].addEventListener('click', function() {
                var sym = this.getAttribute('data-sym');
                var insertText = '';
                if (sym === '\\times') insertText = ' \\times ';
                else if (sym === '\\div') insertText = ' \\div ';
                else if (sym === '\\neq') insertText = ' \\neq ';
                else if (sym === '\\leq') insertText = ' \\leq ';
                else if (sym === '\\geq') insertText = ' \\geq ';
                else if (sym === '\\pi') insertText = ' \\pi ';
                else if (sym === '\\alpha') insertText = ' \\alpha ';
                else if (sym === '\\beta') insertText = ' \\beta ';
                else if (sym === '\\gamma') insertText = ' \\gamma ';
                else if (sym === '\\infty') insertText = ' \\infty ';
                else insertText = sym;
                insertAtCursor(insertText);
            });
        }
        
        // Clear button
        document.getElementById('clearBtn').addEventListener('click', function() {
            if (confirm('Are you sure you want to clear everything?')) {
                latexInput.value = '';
                updatePreview();
                clearUnsaved();
            }
        });
        
        // Copy button
        document.getElementById('copyBtn').addEventListener('click', function() {
            copyLatex();
        });
        
        // Live update on input
        latexInput.addEventListener('input', function() {
            updatePreview();
        });
        
        // Initial preview render
        updatePreview();
        clearUnsaved();
    }

    // ============ INITIALIZATION ============
    function init() {
        console.log('Initializing Restudio Math...');
        setupEventListeners();
        setupKeyboardShortcuts();
        console.log('Restudio Math initialized successfully');
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
