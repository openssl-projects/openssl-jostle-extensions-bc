package org.bouncycastle.jsl.jsse.provider;

import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.jsl.jsse.BCSSLConnection;
import org.bouncycastle.jsl.tls.ChannelBinding;
import org.bouncycastle.jsl.tls.TlsContext;

class ProvSSLConnection
    implements BCSSLConnection
{
    private static final AtomicLong CONNECTION_IDS = new AtomicLong(0L);

    static long allocateConnectionID()
    {
        return CONNECTION_IDS.incrementAndGet();
    }

    protected final ProvTlsPeer tlsPeer;

    ProvSSLConnection(ProvTlsPeer tlsPeer)
    {
        this.tlsPeer = tlsPeer;
    }

    public byte[] exportKeyingMaterial(String asciiLabel, byte[] context_value, int length)
    {
        return getTlsContext().exportKeyingMaterial(asciiLabel, context_value, length);
    }

    public String getApplicationProtocol()
    {
        return JsseUtils.getApplicationProtocol(getTlsContext().getSecurityParametersConnection());
    }

    public byte[] getChannelBinding(String channelBinding)
    {
        if (channelBinding.equals("tls-exporter"))
        {
            return getTlsContext().exportChannelBinding(ChannelBinding.tls_exporter);
        }

        if (channelBinding.equals("tls-server-end-point"))
        {
            return getTlsContext().exportChannelBinding(ChannelBinding.tls_server_end_point);
        }

        if (channelBinding.equals("tls-unique"))
        {
            return getTlsContext().exportChannelBinding(ChannelBinding.tls_unique);
        }

        throw new UnsupportedOperationException();
    }

    public String getID()
    {
        return tlsPeer.getID();
    }

    public ProvSSLSession getSession()
    {
        return tlsPeer.getSession();
    }

    protected TlsContext getTlsContext()
    {
        return tlsPeer.getTlsContext();
    }
}
