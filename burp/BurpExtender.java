package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IMessageEditorController
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;

    private final static String NAME = "ecapture-BurpLoader";
    private PrintWriter stdout;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {

        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.setExtensionName(NAME);
        stdout.println("@Name:ecapture-BurpLoader");
        stdout.println("@Author:depy@Meituan");
        stdout.println("@Version:0.0.1");
        stdout.println("@Introduce:Used to load the plaintext request message captured by the <Ecapture> into the <Repeater> module of the Bursuite");
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // create our UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                Table logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable);
                splitPane.setLeftComponent(scrollPane);


                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);

                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(tabs);

                callbacks.addSuiteTab(BurpExtender.this);

                callbacks.registerHttpListener(BurpExtender.this);
            }
        });
    }

    @Override
    public String getTabCaption()
    {
        return "ecapture-Logger";
    }

    @Override
    public Component getUiComponent()
    {
        return splitPane;
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {

        if (!messageIsRequest)
        {

            synchronized(log)
            {
                int row = log.size();
                log.add(new LogEntry(callbacks.saveBuffersToTempFiles(messageInfo),
                        helpers.analyzeRequest(messageInfo).getUrl(), helpers.analyzeRequest(messageInfo).getMethod(), helpers.analyzeRequest(messageInfo).getUrl().getHost()));
                fireTableRowsInserted(row, row);
            }

        }
    }


    @Override
    public int getRowCount()
    {
        return log.size();
    }

    @Override
    public int getColumnCount()
    {
        return 3;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "URL";
            case 1:
                return "Method";
            case 2:
                return "Host";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.url.toString();
            case 1:
                return logEntry.method.toString();
            case 2:
                return logEntry.host.toString();
            default:
                return "";
        }
    }


    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }


    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }


    private static class LogEntry
    {
        final IHttpRequestResponsePersisted requestResponse;
        final URL url;
        final String method;

        final  String host;

        LogEntry(IHttpRequestResponsePersisted requestResponse, URL url,String method,String host)
        {
            this.requestResponse = requestResponse;
            this.url = url;
            this.method = method;
            this.host = host;
        }
    }
}