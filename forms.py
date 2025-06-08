from flask_wtf import FlaskForm

class CSRFOnlyForm(FlaskForm):
    """A simple form used only for CSRF protection."""
    pass
