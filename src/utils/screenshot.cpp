#include "screenshot.hpp"
#include "../loader/loader.hpp"

#include <d3d11.h>
#include <dxgi1_2.h>
#include <experimental/scope>
#include <format>
#include <gdiplus.h>
#include <objbase.h>
#include <wincodec.h>

namespace utils {
  std::vector<std::uint8_t> capture_primary_monitor_dxgi() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr))
      return {};
    std::experimental::scope_exit co_guard([] {
      CoUninitialize();
    });

    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* ctx = nullptr;
    D3D_FEATURE_LEVEL feature_levels[] = {
            D3D_FEATURE_LEVEL_11_0,
            D3D_FEATURE_LEVEL_10_1,
            D3D_FEATURE_LEVEL_10_0,
            D3D_FEATURE_LEVEL_9_1,
    };
    hr = D3D11CreateDevice(
            nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT, feature_levels, 4,
            D3D11_SDK_VERSION, &device, nullptr, &ctx
    );
    if (FAILED(hr))
      return {};
    std::experimental::scope_exit device_guard([&] {
      device->Release();
      ctx->Release();
    });

    IDXGIDevice* dxgi_device = nullptr;
    hr = device->QueryInterface(__uuidof(IDXGIDevice), reinterpret_cast<void**>(&dxgi_device));
    if (FAILED(hr))
      return {};
    std::experimental::scope_exit dxgi_device_guard([&] {
      dxgi_device->Release();
    });

    IDXGIAdapter* adapter = nullptr;
    hr = dxgi_device->GetParent(__uuidof(IDXGIAdapter), reinterpret_cast<void**>(&adapter));
    if (FAILED(hr))
      return {};
    std::experimental::scope_exit adapter_guard([&] {
      adapter->Release();
    });

    IDXGIOutput* output = nullptr;
    hr = adapter->EnumOutputs(0, &output);
    if (FAILED(hr))
      return {};
    std::experimental::scope_exit output_guard([&] {
      output->Release();
    });

    IDXGIOutput1* output1 = nullptr;
    hr = output->QueryInterface(__uuidof(IDXGIOutput1), reinterpret_cast<void**>(&output1));
    if (FAILED(hr))
      return {};
    std::experimental::scope_exit output1_guard([&] {
      output1->Release();
    });

    IDXGIOutputDuplication* dupl = nullptr;
    hr = output1->DuplicateOutput(device, &dupl);
    if (FAILED(hr))
      return {};
    std::experimental::scope_exit dupl_guard([&] {
      dupl->Release();
    });

    DXGI_OUTDUPL_DESC dupl_desc;
    dupl->GetDesc(&dupl_desc);

    Sleep(100);

    IDXGIResource* resource = nullptr;
    DXGI_OUTDUPL_FRAME_INFO frame_info;
    hr = dupl->AcquireNextFrame(1000, &frame_info, &resource);
    if (FAILED(hr) || !frame_info.LastPresentTime.QuadPart)
      return {};
    std::experimental::scope_exit resource_guard([&] {
      resource->Release();
      dupl->ReleaseFrame();
    });

    ID3D11Texture2D* frame_tex = nullptr;
    hr = resource->QueryInterface(__uuidof(ID3D11Texture2D), reinterpret_cast<void**>(&frame_tex));
    if (FAILED(hr))
      return {};
    std::experimental::scope_exit frame_tex_guard([&] {
      frame_tex->Release();
    });

    D3D11_TEXTURE2D_DESC staging_desc = {
            .Width = dupl_desc.ModeDesc.Width,
            .Height = dupl_desc.ModeDesc.Height,
            .MipLevels = 1,
            .ArraySize = 1,
            .Format = DXGI_FORMAT_B8G8R8A8_UNORM,
            .SampleDesc = {1, 0},
            .Usage = D3D11_USAGE_STAGING,
            .CPUAccessFlags = D3D11_CPU_ACCESS_READ,
    };

    ID3D11Texture2D* staging = nullptr;
    hr = device->CreateTexture2D(&staging_desc, nullptr, &staging);
    if (FAILED(hr))
      return {};
    std::experimental::scope_exit staging_guard([&] {
      staging->Release();
    });

    ctx->CopyResource(staging, frame_tex);

    D3D11_MAPPED_SUBRESOURCE mapped;
    hr = ctx->Map(staging, 0, D3D11_MAP_READ, 0, &mapped);
    if (FAILED(hr))
      return {};
    std::experimental::scope_exit mapped_guard([&] {
      ctx->Unmap(staging, 0);
    });

    IStream* stream = nullptr;
    hr = CreateStreamOnHGlobal(nullptr, TRUE, &stream);
    if (FAILED(hr))
      return {};
    std::experimental::scope_exit stream_guard([&] {
      stream->Release();
    });

    IWICImagingFactory* wic = nullptr;
    hr = CoCreateInstance(
            CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_IWICImagingFactory,
            reinterpret_cast<void**>(&wic)
    );
    if (FAILED(hr))
      return {};
    std::experimental::scope_exit wic_guard([&] {
      wic->Release();
    });

    IWICBitmapEncoder* encoder = nullptr;
    hr = wic->CreateEncoder(GUID_ContainerFormatJpeg, nullptr, &encoder);
    if (FAILED(hr))
      return {};
    std::experimental::scope_exit encoder_guard([&] {
      encoder->Release();
    });

    hr = encoder->Initialize(stream, WICBitmapEncoderNoCache);
    if (FAILED(hr))
      return {};

    IWICBitmapFrameEncode* frame = nullptr;
    IPropertyBag2* props = nullptr;
    hr = encoder->CreateNewFrame(&frame, &props);
    if (FAILED(hr))
      return {};
    std::experimental::scope_exit frame_guard([&] {
      frame->Release();
    });

    if (props) {
      PROPBAG2 prop = {.pstrName = L"ImageQuality"};
      VARIANT val = {.vt = VT_R4, .fltVal = 0.5f};
      props->Write(1, &prop, &val);
      VariantClear(&val);
      props->Release();
    }

    hr = frame->Initialize(nullptr);
    if (FAILED(hr))
      return {};
    hr = frame->SetSize(staging_desc.Width, staging_desc.Height);
    if (FAILED(hr))
      return {};

    WICPixelFormatGUID fmt = GUID_WICPixelFormat32bppBGRA;
    hr = frame->SetPixelFormat(&fmt);
    if (FAILED(hr))
      return {};

    IWICBitmap* wic_bitmap = nullptr;
    hr = wic->CreateBitmapFromMemory(
            staging_desc.Width, staging_desc.Height, GUID_WICPixelFormat32bppBGRA, mapped.RowPitch,
            mapped.RowPitch * staging_desc.Height, static_cast<BYTE*>(mapped.pData), &wic_bitmap
    );
    if (FAILED(hr))
      return {};
    std::experimental::scope_exit wic_bitmap_guard([&] {
      wic_bitmap->Release();
    });

    hr = frame->WriteSource(wic_bitmap, nullptr);
    if (FAILED(hr))
      return {};
    hr = frame->Commit();
    if (FAILED(hr))
      return {};
    hr = encoder->Commit();
    if (FAILED(hr))
      return {};

    STATSTG stat;
    if (stream->Stat(&stat, STATFLAG_NONAME) != S_OK)
      return {};

    std::vector<std::uint8_t> buffer(stat.cbSize.QuadPart);

    LARGE_INTEGER zero{};
    stream->Seek(zero, STREAM_SEEK_SET, nullptr);
    ULONG read = 0;
    stream->Read(buffer.data(), static_cast<ULONG>(stat.cbSize.QuadPart), &read);

    if (!read)
      return {};

    buffer.resize(read);
    return buffer;
  }

  std::vector<std::uint8_t> capture_game_monitor_gdi(HWND target_window) {
    Gdiplus::GdiplusStartupInput gsi;
    ULONG_PTR token;
    if (Gdiplus::GdiplusStartup(&token, &gsi, nullptr) != Gdiplus::Ok)
      return {};
    std::experimental::scope_exit gdiplus_guard([&] {
      Gdiplus::GdiplusShutdown(token);
    });

    if (!target_window)
      target_window = GetDesktopWindow();
    MONITORINFOEXW mi{};
    mi.cbSize = sizeof(mi);
    if (!GetMonitorInfoW(MonitorFromWindow(target_window, MONITOR_DEFAULTTONEAREST), &mi))
      return {};

    const int w = mi.rcMonitor.right - mi.rcMonitor.left;
    const int h = mi.rcMonitor.bottom - mi.rcMonitor.top;

    HDC screen_dc = CreateDCW(nullptr, mi.szDevice, nullptr, nullptr);
    if (!screen_dc)
      return {};
    std::experimental::scope_exit screen_dc_guard([&] {
      DeleteDC(screen_dc);
    });

    HDC mem_dc = CreateCompatibleDC(screen_dc);
    if (!mem_dc)
      return {};
    std::experimental::scope_exit mem_dc_guard([&] {
      DeleteDC(mem_dc);
    });

    HBITMAP bmp = CreateCompatibleBitmap(screen_dc, w, h);
    if (!bmp)
      return {};
    std::experimental::scope_exit bmp_guard([&] {
      DeleteObject(bmp);
    });

    HGDIOBJ old_bmp = SelectObject(mem_dc, bmp);
    if (!old_bmp)
      return {};

    BOOL blt_ok = BitBlt(mem_dc, mi.rcMonitor.left, mi.rcMonitor.top, w, h, screen_dc, 0, 0, SRCCOPY | CAPTUREBLT);
    SelectObject(mem_dc, old_bmp);
    if (!blt_ok)
      return {};

    CLSID clsid_jpeg{};
    UINT count = 0, size = 0;
    Gdiplus::GetImageEncodersSize(&count, &size);
    std::vector<std::uint8_t> codec_buf(size);
    auto* codecs = reinterpret_cast<Gdiplus::ImageCodecInfo*>(codec_buf.data());
    Gdiplus::GetImageEncoders(count, size, codecs);
    bool found = false;
    for (UINT i = 0; i < count; i++) {
      if (std::wstring_view(codecs[i].MimeType) == L"image/jpeg") {
        clsid_jpeg = codecs[i].Clsid;
        found = true;
        break;
      }
    }
    if (!found)
      return {};

    IStream* stream = nullptr;
    if (CreateStreamOnHGlobal(nullptr, TRUE, &stream) != S_OK)
      return {};
    std::experimental::scope_exit stream_guard([&] {
      stream->Release();
    });

    Gdiplus::EncoderParameters params;
    params.Count = 1;
    params.Parameter[0].Guid = Gdiplus::EncoderQuality;
    params.Parameter[0].Type = Gdiplus::EncoderParameterValueTypeLong;
    params.Parameter[0].NumberOfValues = 1;
    ULONG quality = 50;
    params.Parameter[0].Value = &quality;

    Gdiplus::Bitmap bitmap(bmp, nullptr);
    if (bitmap.Save(stream, &clsid_jpeg, &params) != Gdiplus::Ok)
      return {};

    STATSTG stat;
    if (stream->Stat(&stat, STATFLAG_NONAME) != S_OK)
      return {};

    std::vector<std::uint8_t> buffer(stat.cbSize.QuadPart);

    LARGE_INTEGER zero{};
    stream->Seek(zero, STREAM_SEEK_SET, nullptr);
    ULONG read = 0;
    stream->Read(buffer.data(), static_cast<ULONG>(stat.cbSize.QuadPart), &read);

    if (!read)
      return {};

    buffer.resize(read);
    return buffer;
  }

  void submit_screenshot_report(const std::string& reason) {
    std::vector<std::uint8_t> buffer = utils::capture_primary_monitor_dxgi();

    if (!buffer.empty()) {
      return loader::append_report(
              message_id::screenshot, reason.c_str(), reason.size(), nullptr, 0, buffer.data(), buffer.size()
      );
    }

    const std::string dxgi_error_tag = std::format("SS_{:X}", GetLastError());
    loader::append_report(
            message_id::screenshot_error, reason.c_str(), reason.size(), dxgi_error_tag.c_str(), dxgi_error_tag.size(),
            nullptr, 0
    );

    // fallback
    const std::string blt_reason = reason + "_BLT";
    buffer = capture_game_monitor_gdi();

    if (!buffer.empty()) {

      return loader::append_report(
              message_id::screenshot, blt_reason.c_str(), blt_reason.size(), nullptr, 0, buffer.data(), buffer.size()
      );
    }

    const std::string gdi_error_tag = std::format("SS_BLT_{:X}", GetLastError());

    return loader::append_report(
            message_id::screenshot_error, blt_reason.c_str(), blt_reason.size(), gdi_error_tag.c_str(),
            gdi_error_tag.size(), nullptr, 0
    );
  }

} // namespace utils
