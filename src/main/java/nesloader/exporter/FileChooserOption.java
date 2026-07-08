package nesloader.exporter;

import java.awt.BorderLayout;
import java.awt.Component;
import java.io.File;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.util.Option;
import ghidra.util.filechooser.ExtensionFileFilter;

/**
 * Exporter option holding a file path (String value), edited via a text field
 * combined with a "..." button that opens a {@link GhidraFileChooser}.
 */
class FileChooserOption extends Option {

    private final String filterDescription;
    private final String[] filterExtensions;

    FileChooserOption(String name, String path,
                      String filterDescription, String... filterExtensions) {
        super(name, path);
        this.filterDescription = filterDescription;
        this.filterExtensions  = filterExtensions;
    }

    @Override
    public Component getCustomEditorComponent() {
        JTextField field = new JTextField((String) getValue(), 20);
        field.setName(getName());
        field.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e)  { setValue(field.getText()); }
            @Override public void removeUpdate(DocumentEvent e)  { setValue(field.getText()); }
            @Override public void changedUpdate(DocumentEvent e) { setValue(field.getText()); }
        });

        JPanel panel = new JPanel(new BorderLayout());

        JButton browse = new JButton("...");
        browse.addActionListener(e -> {
            GhidraFileChooser chooser = new GhidraFileChooser(panel);
            chooser.setTitle(getName());
            chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
            chooser.setFileFilter(
                ExtensionFileFilter.forExtensions(filterDescription, filterExtensions));

            String current = (String) getValue();
            if (current != null && !current.isBlank()) {
                chooser.setSelectedFile(new File(current));
            }

            File selected = chooser.getSelectedFile();
            chooser.dispose();
            if (selected != null) {
                field.setText(selected.getAbsolutePath());
            }
        });

        panel.add(field,  BorderLayout.CENTER);
        panel.add(browse, BorderLayout.EAST);
        return panel;
    }

    @Override
    public Option copy() {
        return new FileChooserOption(getName(), (String) getValue(),
            filterDescription, filterExtensions);
    }
}
