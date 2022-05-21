//
//  marshaled.swift
//  
//
//  Created by Brandon Toms on 5/1/22.
//

import Foundation

/// Base64 Padded
struct MarshaledData {
    /// A marshaled (base64padded) private 1024bit RSA key
    ///
    /// - Note: Generated via SecKey  in swift-libp2p v0.1.0
    static let PRIVATE_RSA_KEY_1024 = "CAAS4AQwggJcAgEAAoGBAN2RGr5akx6ZTvpr3lZfSBU2YAo8s9Zu9B3XQcSjQPZyFTr3c3+XAJDIkpwSaXuc2EUdGP2yxzkShAt1hnibwESVV6lXtomB9mfIdvlh7J4Y1kP9wwF1KedTP4MNlVvaHZ7K+/5lyp+GObNAJJU/YnY/kz6kwUI7r0J948xDJdnlAgMBAAECgYB34EQ57UNf8M58StRWouKbJ3o6z7D1Ob62Tnp062cAb6Tw7GT/CTHzI7G+429Sw/93FVEqIgoL5OqwUHva0VnqP4dunGHHsG+KGwVqL0/6Sr/qkg9Mc3B7StI7QvFgnKQtzMlbFN6ijF0rGXaAh4gcnxzcJyT/KnxePbIyNOtfgQJBAPcbEmXbwIcPyT6QOwR8wwtDh+5GFSndJontFcd7ntC+6mqDuFaCpAd7yBeQcBOvHWOp/FbCBzJCEXFLWFcKgLECQQDlirT7AaujIMODtdBAG+Cxk62XmMX7AkD40Twn/URHJr91oUTJkZmLP6XjGR6kzRAeKfQr/3HpPnWx1uBBM9l1AkEAxD7rzZlIvfr7iIRjWpz7CecH/WQLSsQn50IzGcpDxuTYpt8Vdx8pxge4UX6UhA1++bf2f7B4pqFx2NhNwFLHAQJAMxgZCPZqOjmEy8CgxmRuM5jnvyLmjuUFiV0pws0BccUSQSDQqv2Z7AES7+YbiBuNRumXzGNj+8NHd3qZGGpuMQJAIgoySo2stOX3gTnlF5sPXFuiUjth3vhuzms15yeSqOs22Xew05TqVhoqYuWWjk1E2+Af5YAHKIbOEiVqSnzZEQ=="
    /// A marshaled (base64padded) public 1024bit RSA key
    ///
    /// - Note: Generated via SecKey in swift-libp2p v0.1.0
    static let PUBLIC_RSA_KEY_1024 = "CAASogEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN2RGr5akx6ZTvpr3lZfSBU2YAo8s9Zu9B3XQcSjQPZyFTr3c3+XAJDIkpwSaXuc2EUdGP2yxzkShAt1hnibwESVV6lXtomB9mfIdvlh7J4Y1kP9wwF1KedTP4MNlVvaHZ7K+/5lyp+GObNAJJU/YnY/kz6kwUI7r0J948xDJdnlAgMBAAE="
    
    /// A marshaled (base64padded) private 2048bit RSA key
    ///
    /// - Note: I think this came from a GO or JS test fixture
    static let PRIVATE_RSA_KEY_2048 = "CAASpgkwggSiAgEAAoIBAQC2SKo/HMFZeBml1AF3XijzrxrfQXdJzjePBZAbdxqKR1Mc6juRHXij6HXYPjlAk01BhF1S3Ll4Lwi0cAHhggf457sMg55UWyeGKeUv0ucgvCpBwlR5cQ020i0MgzjPWOLWq1rtvSbNcAi2ZEVn6+Q2EcHo3wUvWRtLeKz+DZSZfw2PEDC+DGPJPl7f8g7zl56YymmmzH9liZLNrzg/qidokUv5u1pdGrcpLuPNeTODk0cqKB+OUbuKj9GShYECCEjaybJDl9276oalL9ghBtSeEv20kugatTvYy590wFlJkkvyl+nPxIH0EEYMKK9XRWlu9XYnoSfboiwcv8M3SlsjAgMBAAECggEAZtju/bcKvKFPz0mkHiaJcpycy9STKphorpCT83srBVQi59CdFU6Mj+aL/xt0kCPMVigJw8P3/YCEJ9J+rS8BsoWE+xWUEsJvtXoT7vzPHaAtM3ci1HZd302Mz1+GgS8Epdx+7F5p80XAFLDUnELzOzKftvWGZmWfSeDnslwVONkL/1VAzwKy7Ce6hk4SxRE7l2NE2OklSHOzCGU1f78ZzVYKSnS5Ag9YrGjOAmTOXDbKNKN/qIorAQ1bovzGoCwx3iGIatQKFOxyVCyO1PsJYT7JO+kZbhBWRRE+L7l+ppPER9bdLFxs1t5CrKc078h+wuUr05S1P1JjXk68pk3+kQKBgQDeK8AR11373Mzib6uzpjGzgNRMzdYNuExWjxyxAzz53NAR7zrPHvXvfIqjDScLJ4NcRO2TddhXAfZoOPVH5k4PJHKLBPKuXZpWlookCAyENY7+Pd55S8r+a+MusrMagYNljb5WbVTgN8cgdpim9lbbIFlpN6SZaVjLQL3J8TWH6wKBgQDSChzItkqWX11CNstJ9zJyUE20I7LrpyBJNgG1gtvz3ZMUQCn3PxxHtQzN9n1P0mSSYs+jBKPuoSyYLt1wwe10/lpgL4rkKWU3/m1Myt0tveJ9WcqHh6tzcAbb/fXpUFT/o4SWDimWkPkuCb+8j//2yiXk0a/T2f36zKMuZvujqQKBgC6B7BAQDG2H2B/ijofp12ejJU36nL98gAZyqOfpLJ+FeMz4TlBDQ+phIMhnHXA5UkdDapQ+zA3SrFk+6yGk9Vw4Hf46B+82SvOrSbmnMa+PYqKYIvUzR4gg34rL/7AhwnbEyD5hXq4dHwMNsIDq+l2elPjwm/U9V0gdAl2+r50HAoGALtsKqMvhv8HucAMBPrLikhXP/8um8mMKFMrzfqZ+otxfHzlhI0L08Bo3jQrb0Z7ByNY6M8epOmbCKADsbWcVre/AAY0ZkuSZK/CaOXNX/AhMKmKJh8qAOPRY02LIJRBCpfS4czEdnfUhYV/TYiFNnKRj57PPYZdTzUsxa/yVTmECgYBr7slQEjb5Onn5mZnGDh+72BxLNdgwBkhO0OCdpdISqk0F0Pxby22DFOKXZEpiyI9XYP1C8wPiJsShGm2yEwBPWXnrrZNWczaVuCbXHrZkWQogBDG3HGXNdU4MAWCyiYlyinIBpPpoAJZSzpGLmWbMWh28+RJS6AQX6KHrK1o2uw=="
    /// A marshaled (base64padded) public 2048bit RSA key
    ///
    /// - Note: I think this came from a GO or JS test fixture
    static let PUBLIC_RSA_KEY_2048 = "CAASpgIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2SKo/HMFZeBml1AF3XijzrxrfQXdJzjePBZAbdxqKR1Mc6juRHXij6HXYPjlAk01BhF1S3Ll4Lwi0cAHhggf457sMg55UWyeGKeUv0ucgvCpBwlR5cQ020i0MgzjPWOLWq1rtvSbNcAi2ZEVn6+Q2EcHo3wUvWRtLeKz+DZSZfw2PEDC+DGPJPl7f8g7zl56YymmmzH9liZLNrzg/qidokUv5u1pdGrcpLuPNeTODk0cqKB+OUbuKj9GShYECCEjaybJDl9276oalL9ghBtSeEv20kugatTvYy590wFlJkkvyl+nPxIH0EEYMKK9XRWlu9XYnoSfboiwcv8M3SlsjAgMBAAE="
    
    /// A marshaled (base64padded) private 3072bit RSA key
    ///
    /// - Note: Generated via SecKey in swift-libp2p v0.1.0
    static let PRIVATE_RSA_KEY_3072 = "CAAS5w0wggbjAgEAAoIBgQDZSv/m42dihS3dBZ6+265BQWgvCf5oPRwQieekWSpy14Zk+FaWAORry9/1X7HZYqTCrFNo9JUt9Qo9HDv//aGcIs6zhuSYNCy85hCBAUd/S9TTzx5qeimUZ1/Gm0VMPtpxUhZqt2V23/BcBFsUO40f0uibOA3BkftIMlNCJptlZ/cAlULFKs5bua6tEiWycuOrcbigvzrkbc/vDaRCOBPsLGOY/ljSpc74r75sEC9brbBPxMknpJ8o4YG/V1jo+t15WbILqPPEKm1m8RRuTZSeSOw1S/GlcD1c6HCeX9ms6kmA0LcOv/eSmHqiLCtXybOJFPxTvfbBlQyAwUf4gUj8HDrgfq9i6ldlEP6RfduBZPMvX7yEVDmoz1KtSX+usXC73gfwlZU9Rrwg8jkR9bl1G8c5J8nKiWIdxgq9HGY/CVVl9IsXf0m+0NNLEAClBIUbp9+7QH72wrnzcI6eAqAxMyUGcuqxcXQC4RMuCPE19eeUA4L+hbmyXzXAG+jMWDsCAwEAAQKCAYAImcFbQDD9Y0wXbXuFDmjtSEt5YSnisliEBxFWHfliJkm5gWLb+RkRczZgHfOKKS9gTTXX96ZX9VT8ajutvDpDVdVcocA2jgofR/PrR0OvNC8uWwpXKJKwvw65a7fodqxqw9cDTlMDy4VV/w4j1N+XHN/8FNHmkYKirutAuQp5jw3lxgKojzMvyj+xtgAr+gQs6wllw2vvUrFiQuX3gQS42mDu01JstAdnLH2bBWD6fft2jNFxckCie5qJGkn4nsVGtjbFBKO9btOtQtJ7s23fGbvkZOtcul+I8pY+UYeH3OrSxIiClW9Gy7uSQn69n6jHTwCGecsoShyZN/iFqZdIKUs3muhrQuyAQJCp2fVpkyO2+ZL6TGPrlgrpMkGDogujHj2vlR8FIShVy8MeLwQYOae1vY/ecDxlvsoU6ViOE1dfhFIdusINeceL1nRVFVaRZ/aBElKsCDlqi1VNTOVWR+PBvXzogWbil3I4WZctqsbx19Z3v5bANuVLHOBc9AECgcEA7vMVZtuLIQKEDXS16s0gr633dpTBOcuEMzjuzib6i95yjpWB/NgDdnxUFKheb3r860REXwFxt6Sup95RPnHSMrBe5V5wPTKm8D7qvfShLPoGQ6F/2RdpwwftFlVpzXYo3TRVUHHzvpcxKsqVER8DGfVuX9iSv0qwHifEcVp/k4BZgcJZfGfKWBAPehM7JLhVAdsi4JeOz/21WCtcpJICG1dsRXlpiDF5qyWhdZNcurVE0LfjzziM9VnFADRnpFEBAoHBAOjMUCL8T12fadWWcsrDmpDjsNWICinxR7y4eA1uks21UfGz4HtPydkZWd85F7PD6qD+uWOhtmARcET+bMudrkZOHdESbYO8DhhXnMQUQUi3xp4+VyFVEW35SNj1yrCFw7VsO9IxldMlbj9faJkBHwqk34VMSvqnnkMztQ4I0AdTjHw1MM+0oetob5LQJauOWBhdn1e3Xz2TulD7ZAvGzx3UajvRkfBf0OTTPzY1R/jKJfVaMnhTcQz+lKvzyzCtOwKBwGgHRGYHZsb0RXFmQlz6+SQC5R2nHYh/5go22yC9L479RXp19KWTlc5bym9D7fky3jG/AtUp18xP0goba9t3yj9vMaFCQDMkfjFR8vjIK/Nc1qVTBkoJO25BYSK8BNgCfT/wrMPdGHT9ddZfZA6UJdGDXI41x42ogoxeW9PNxoT89/raFgNnXFyCgXpwLOuLpNauBL0qvm4m0nCUUD0FpA0rPmPwu9UjVQkB1Q1PHqvahx8nL/Ljd9rJPk8cgZK0AQKBwQCNsTWhZbKkyE9xagXqdg3Q3FUYUpnlF29TZW/ktQVzYUZD9/jM9S5lDjIOVMChcMCRRxjtlFLdvB96TuVHNW0Ka6doRnATu1VU6ZaIHc/yg7DHRihgKFfYeN8m9stsj64j8YGjmPyZLHIi7l5Kqk0LfHhzuJD2aSlBu+oaZbDAlNCwFOvlsArRrpoiYMBc3+GsyuceS4UThKPlgG1PYa1UeaJDUHYkOR16+TzDMMDio59g64pGhHsNrrIsytFEilsCgcBPwA8tYHSyzbxmc7UdPlL4ds0XXhgvytDIpufv3iq3MNH/NvRuFPhyz/yrWxSqeg11WJc/RqJ5BIiLIQ6kS64ZTM26Ia4pHe5/mPFGz8Gy5V27CRQWd4pE6klkHRfsU3FJLM4M6MHRSJiTng0ECBV+iQCJ5JAoGsMW3cRhLUS0BGW3lkckpQ4Waiid9VRfMbvYwWSY6sLMmvCWpvP7rHYGB8N0E++p91p7EvNVW93LE+HnqhgMVWl0Wu+SgYIaCi0="
    /// A marshaled (base64padded) public 3072bit RSA key
    ///
    /// - Note: Generated via SecKey in swift-libp2p v0.1.0
    static let PUBLIC_RSA_KEY_3072 = "CAASpgMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDZSv/m42dihS3dBZ6+265BQWgvCf5oPRwQieekWSpy14Zk+FaWAORry9/1X7HZYqTCrFNo9JUt9Qo9HDv//aGcIs6zhuSYNCy85hCBAUd/S9TTzx5qeimUZ1/Gm0VMPtpxUhZqt2V23/BcBFsUO40f0uibOA3BkftIMlNCJptlZ/cAlULFKs5bua6tEiWycuOrcbigvzrkbc/vDaRCOBPsLGOY/ljSpc74r75sEC9brbBPxMknpJ8o4YG/V1jo+t15WbILqPPEKm1m8RRuTZSeSOw1S/GlcD1c6HCeX9ms6kmA0LcOv/eSmHqiLCtXybOJFPxTvfbBlQyAwUf4gUj8HDrgfq9i6ldlEP6RfduBZPMvX7yEVDmoz1KtSX+usXC73gfwlZU9Rrwg8jkR9bl1G8c5J8nKiWIdxgq9HGY/CVVl9IsXf0m+0NNLEAClBIUbp9+7QH72wrnzcI6eAqAxMyUGcuqxcXQC4RMuCPE19eeUA4L+hbmyXzXAG+jMWDsCAwEAAQ=="
    
    /// A marshaled (base64padded) private 4096bit RSA key
    ///
    /// - Note: Generated via SecKey in swift-libp2p v0.1.0
    static let PRIVATE_RSA_KEY_4096 = "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"
    /// A marshaled (base64padded) public 4096bit RSA key
    ///
    /// - Note: Generated via SecKey in swift-libp2p v0.1.0
    static let PUBLIC_RSA_KEY_4096 = "CAASpgQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQD3FcFG9iBVJA51KOMXlgDEeizTKBmJ25BpvX+RfhhDyl7NtEKO3WzidPuvpUngc39TmXbyN8ZlOCiMR7AOeRlBrcGgeeFXAljXUnwcGAnG8u19WeF8x64Xzl5I48i/hN/zxQ/YHGyyyvMOowh0s/XEmsbzZb8fmeRhkIeGt1DY16tAnewmV83Vn596yZHtA6RIAQMtcdCwVB0+DfZ+WPya3FHuTdVztmUzfKCatCUNr9NI4TXHgf+7BRu2idVbQ3khh/axAo+0c2htHs6b+AQ1rxZoEoB2f4YUL6ICj8zkJVC4pE1hraRMLR4ExPUb0mvy/DJq5T7+OcxO/Y/dskpsdyo0j00simHPeEmUuP45A7AbYTr7MKInMqlKBOLM+yORn8CDlKiT6cDkLD2oowUtf0wI8LK0D+fAg/5GwJtSg2uHRUWQFv19KkOUHuR8T/HYyGelBsKPZZ5O46BLD7PSYdTFHvNiURxOQKmZYeGhuBJ2wp0q6R+Evvdvwcu+PcGCQIuQb9mAdtHeS2oZjCxY+czsYy2pUHxxuGSpBI+aQLwRMFhpm0B/WMcjLOLFH88qNa7U8ksxZpLZufnBxuiqfX+FGKga3Jj7dv1oV+oFxTvndHhZL0JQDTylnuv79T1KYOVzxNWAJsaPXKUUbOhm4kdDHUY2RhEJMh2QVDitcwIDAQAB"
}
