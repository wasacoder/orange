(function (L) {
    var _this = null;
    L.Status = L.Status || {};
    _this = L.Status = {
        data: {
        	timer: null,
        	requestChart: null,
        	qpsChart: null,
        	responseChart: null,
        	trafficChart: null,
        	stateChart: [],
        	interval: 3000,

            lastTotalRequstCount: 0,
            is_first_request: true,
            try_times: 5
        },
 
        init: function () {
        	
            _this.getData();
        	_this.startTimer();

        	$("#time-set a").click(function(){
        		$("#time-set a").each(function(){
	                $(this).removeClass("active")
	            });

	            $(this).addClass("active");
        	});

            $("#view-set a").click(function(){
                $("#view-set a").each(function(){
                    $(this).removeClass("active")
                });

                $(this).addClass("active");
                if($(this).hasClass("data-view")){
                    $("#data-section").css("display", "block");
                    $("#chart-section").css("display", "none");
                }else if($(this).hasClass("chart-view")){
                    $("#data-section").css("display", "none");
                    $("#chart-section").css("display", "block");

                    _this.initRequestStatus();
                    _this.initQPSStatus();
                    _this.initReponseStatus();
                    _this.initTrafficStatus();
                    _this.initStateStatus("2xx");
                    _this.initStateStatus("3xx");
                    _this.initStateStatus("4xx");
                    _this.initStateStatus("5xx");
                }
            });

        	$(document).on("click", ".timer_interval", function(){
        		var interval  = parseInt($(this).attr("data-interval"), 10);
        		_this.data.interval = interval;
        		_this.startTimer(interval);
        	});
        },

        renderTimestamp: function(loadTimestamp){
            var timemiles = (new Date()).getTime() / 1000 - loadTimestamp;
            var days = Math.floor(timemiles / (3600 * 24));
            timemiles -= days * 3600 * 24;
            var hours = Math.floor(timemiles / 3600)
            timemiles -= hours * 3600;
            var minutes = Math.floor(timemiles / 60);
            return days + "??? " + hours + "?????? " + minutes + "???";
        },

        renderDataView: function(data){
            var tpl = $("#status-tpl").html();
            var qps = (data.total_count - _this.data.lastTotalRequstCount)/(_this.data.interval/1000)
            _this.data.lastTotalRequstCount = data.total_count;
            data.qps = qps;
            data.load_timestamp = _this.renderTimestamp(data.load_timestamp);
            var html = juicer(tpl, {
                status: data
            });
            $("#data-section").html(html);
        },

        renderChartView: function(data){
            var axisData = APP.Common.formatTime();
            //request ??????
            var requestOption = _this.data.requestChart.getOption();
            var data0 = requestOption.series[0].data;
            var data1 = requestOption.series[1].data;
            data0.shift();
            data0.push(data.total_count);
            data1.shift();
            data1.push(data.total_count - data.total_success_count);
            requestOption.xAxis[0].data.shift();
            requestOption.xAxis[0].data.push(axisData);
            _this.data.requestChart.setOption(requestOption);

            //qps??????
            var qpsOption = _this.data.qpsChart.getOption();
            if(_this.data.is_first_request){
                _this.data.is_first_request=false;
            }else{
                data0 = qpsOption.series[0].data;
                data0.shift();
                data0.push((data.total_count - _this.data.lastTotalRequstCount)/(_this.data.interval/1000));
                qpsOption.xAxis[0].data.shift();
                qpsOption.xAxis[0].data.push(axisData);
                _this.data.qpsChart.setOption(qpsOption);
            }
            _this.data.lastTotalRequstCount = data.total_count;

            //??????????????????
            var responseOption = _this.data.responseChart.getOption();
            data0 = responseOption.series[0].data;
            data0.shift();
            data0.push(data.total_request_time);
            responseOption.xAxis[0].data.shift();
            responseOption.xAxis[0].data.push(axisData);
            _this.data.responseChart.setOption(responseOption);

            //????????????
            var trafficOption = _this.data.trafficChart.getOption();
            var data0 = trafficOption.series[0].data;
            var data1 = trafficOption.series[1].data;
            data0.shift();
            data0.push(Math.round(data.traffic_read/1024/1024));
            data1.shift();
            data1.push(Math.round(data.traffic_write/1024/1024));
            trafficOption.xAxis[0].data.shift();
            trafficOption.xAxis[0].data.push(axisData);
            _this.data.trafficChart.setOption(trafficOption);

            //HTTP status??????
            var stateOption = _this.data.stateChart.getOption();
            data0 = stateOption.series[0].data;
            data0.shift();
            data0.push( data["request_2xx"]);

            data1 = stateOption.series[1].data;
            data1.shift();
            data1.push( data["request_3xx"]);

            var data2 = stateOption.series[2].data;
            data2.shift();
            data2.push( data["request_4xx"]);

            var data3 = stateOption.series[3].data;
            data3.shift();
            data3.push( data["request_5xx"]);
            _this.data.stateChart.setOption(stateOption);
        },

       	startTimer:function(interval){
        	interval = interval || 3000; //??????3???????????????
        	if(_this.data.timer){
	        	clearInterval(_this.data.timer);
	        }

	        _this.data.try_times = 5;
	        _this.data.lastTotalRequstCount = 0;
	        _this.data.is_first_request = true;
	        _this.data.timer =  setInterval(function (){
            	_this.getData();
	        }, interval);
        },

        getData: function(){
            $.ajax({
                url : '/stat/status',
                type : 'get',
                cache: false,
                data : {},
                dataType : 'json',
                success : function(result) {
                    if(result.success){
                        $("#tip-section span").text("?????????????????????: " + L.Common.formatTime());
                        $("#tip-section").css("display", "block");

                        var data = result.data || {};

                        if($("#view-set .data-view").hasClass("active")){
                            _this.renderDataView(data);
                        }else if($("#view-set .chart-view").hasClass("active")){
                            _this.renderChartView(data);
                        }
                    }else{
                        APP.Common.showErrorTip("????????????", result.msg);
                        _this.data.try_times--;
                        if(_this.data.try_times<0){
                            clearInterval(_this.data.timer);
                            APP.Common.showErrorTip("????????????", "???????????????????????????????????????????????????");
                        }
                    }
                },
                error : function() {
                    _this.data.try_times--;
                    if(_this.data.try_times<0){
                        clearInterval(_this.data.timer);
                        APP.Common.showErrorTip("????????????", "???????????????????????????????????????????????????");

                    }else{
                        APP.Common.showErrorTip("??????", "????????????????????????");
                    }
                    
                }
            });
        },

        initRequestStatus: function(){
        	var option = {
	            title : {
	                text: '????????????',
	                subtext: '',
                    left:'10px',
	            },
                grid: {
                    left: '20px',
                    right: '20px',
                    bottom: '30px',
                    containLabel: true
                },
	            tooltip : {
	                trigger: 'axis'
	            },
	            legend: {
	                data:['????????????','????????????']
	            },
	            toolbox: {
	                show: true,
                    right:"20px",
			        feature: {
			            dataView: {readOnly: false},
			            saveAsImage: {}
			        }
	            },
	            xAxis : [
	                {
	                    type : 'category',
	                    boundaryGap : false,
	                    data : (function (){
	                        var now = new Date();
	                        var res = [];
	                        var len = 100;
	                        while (len--) {
	                            res.unshift(APP.Common.formatTime());
	                            now = new Date(now - 200);
	                        }
	                        return res;
	                    })()
	                }
	            ],
	            yAxis : [
	                {
	                    type : 'value',
	                    scale: true,
	                    name : '??????'
	                }
	            ],
	            series : [
	                {
	                    name:'????????????',
	                    type:'line',
                        itemStyle: {
                            normal: {
                                color: '#03A1F7'
                            }
                        },
	                    data:(function (){
	                        var res = [];
	                        var len = 100;
	                        while (len--) {
	                          res.push(0);
	                        }
	                        return res;
	                    })()
	                },

	                {
	                    name:'????????????',
	                    type:'line',
                        itemStyle: {
                            normal: {
                                color: '#F75903'
                            }
                        },
	                    data:(function (){
	                        var res = [];
	                        var len = 100;
	                        while (len--) {
	                          res.push(0);
	                        }
	                        return res;
	                    })()
	                }
	            ]
	        };

	        var requestChart = echarts.init(document.getElementById('request-area'));
	        requestChart.setOption(option);
	        _this.data.requestChart = requestChart;
        },

        initQPSStatus: function(){
        	var option = {
	            title : {
                    text: 'QPS??????',
                    subtext: '',
                    left:'26px'
	            },
                grid: {
                    left: '33px',
                    right: '33px',
                    bottom: '30px',
                    containLabel: true
                },
	            tooltip : {
	                trigger: 'axis'
	            },
	            legend: {
	                data:['QPS']
	            },
	             toolbox: {
                     show: true,
                     right:"34px",
                     feature: {
                         dataView: {readOnly: false},
                         saveAsImage: {}
                     }
	            },
	            xAxis : [
	                {
	                    type : 'category',
	                    boundaryGap : false,
	                    data : (function (){
	                        var now = new Date();
	                        var res = [];
	                        var len = 100;
	                        while (len--) {
	                            res.unshift(APP.Common.formatTime());
	                            now = new Date(now - 200);
	                        }
	                        return res;
	                    })()
	                }
	            ],
	            yAxis : [
	                {
	                    type : 'value',
	                    scale: true,
	                    name : 'Query'
	                }
	            ],
	            series : [
	                {
	                    name:'QPS',
	                    type:'line',
                        itemStyle: {
                            normal: {
                                color: '#ECA047'
                            }
                        },
                        areaStyle: {normal: {}},
	                    data:(function (){
	                        var res = [];
	                        var len = 100;
	                        while (len--) {
	                          res.push(0);
	                        }
	                        return res;
	                    })()
	                }
	            ]
	        };

	        var qpsChart = echarts.init(document.getElementById('qps-area'));
	        qpsChart.setOption(option);
	        _this.data.qpsChart = qpsChart;
        },

        initReponseStatus: function(){
        	var option = {
	            title : {
                    text: '??????????????????',
                    left:'10px',
                    subtext: ''
	            },
                grid: {
                    left: '15px',
                    right: '10px',
                    bottom: '30px',
                    containLabel: true
                },
	            tooltip : {
	                trigger: 'axis'
	            },
	            legend: {
	                data:['????????????']
	            },
	            xAxis : [
	                {
	                    type : 'category',
	                    boundaryGap : false,
	                    data : (function (){
	                        var now = new Date();
	                        var res = [];
	                        var len = 100;
	                        while (len--) {
	                            res.unshift(APP.Common.formatTime());
	                            now = new Date(now - 200);
	                        }
	                        return res;
	                    })()
	                }
	            ],
	            yAxis : [
	                {
	                    type : 'value',
	                    scale: true,
	                    name : '???'
	                }
	            ],
	            series : [
	                {
	                    name:'????????????',
	                    type:'line',
	                    smooth: true,
	                    symbol: 'none',
	                    data:(function (){
	                        var res = [];
	                        var len = 100;
	                        while (len--) {
	                          res.push(0);
	                        }
	                        return res;
	                    })()
	                }
	            ]
	        };

	        var responseChart = echarts.init(document.getElementById('response-area'));
	        responseChart.setOption(option);
	        _this.data.responseChart = responseChart;
        },

		initTrafficStatus: function(){
        	var option = {
	            title : {
                    text: '????????????',
                    subtext: ''
	            },
                grid: {
                    left: '15px',
                    right: '10px',
                    bottom: '30px',
                    containLabel: true
                },
	            tooltip : {
	                trigger: 'axis'
	            },
	            legend: {
	                data:['??????','??????']
	            },
	            xAxis : [
	                {
	                    type : 'category',
	                    boundaryGap : false,
	                    data : (function (){
	                        var now = new Date();
	                        var res = [];
	                        var len = 100;
	                        while (len--) {
	                            res.unshift(APP.Common.formatTime());
	                            now = new Date(now - 200);
	                        }
	                        return res;
	                    })()
	                }
	            ],
	            yAxis : [
	                {
	                    type : 'value',
	                    scale: true,
	                    name : 'mbytes'
	                }
	            ],
	            series : [
	                {
	                    name:'??????',
	                    type:'line',
	                    smooth: true,
	                    data:(function (){
	                        var res = [];
	                        var len = 100;
	                        while (len--) {
	                          res.push(0);
	                        }
	                        return res;
	                    })()
	                },

	                {
	                    name:'??????',
	                    type:'line',
	                    data:(function (){
	                        var res = [];
	                        var len = 100;
	                        while (len--) {
	                          res.push(0);
	                        }
	                        return res;
	                    })()
	                }
	            ]
	        };

	        var trafficChart = echarts.init(document.getElementById('traffic-area'));
	        trafficChart.setOption(option);
	        _this.data.trafficChart = trafficChart;
        },

        initStateStatus: function(code){
            var option = {
                title : {
                    text: 'HTTP Status ??????',
                    left:'26px',
                    subtext: ''
                },
                grid: {
                    left: '36px',
                    right: '30px',
                    bottom: '30px',
                    containLabel: true
                },
                tooltip : {
                    trigger: 'axis',
                    axisPointer : {// ??????????????????????????????????????????
                        type : 'shadow'// ??????????????????????????????'line' | 'shadow'
                    }
                },
                legend: {
                    data:['2xx??????', '3xx??????','4xx??????','5xx??????']
                },
                xAxis : [
                    {
                        type : 'value'
                    }
                ],
                yAxis : [
                    {
                        type : 'category',
                        axisTick : {show: false},
                        data : ['']
                    }
                ],
                series : [
                    {
                        name:'2xx??????',
                        type:'bar',
                        label: {
                            normal: {
                                show: true,
                                position: 'inside'
                            }
                        },
                        itemStyle: {
                            normal: {
                                color: '#269EBD'
                            }
                        },
                        data:[0]
                    },
                    {
                        name:'3xx??????',
                        type:'bar',
                        label: {
                            normal: {
                                show: true
                            }
                        },
                        data:[0]
                    },
                    {
                        name:'4xx??????',
                        type:'bar',
                        label: {
                            normal: {
                                show: true
                            }
                        },
                        itemStyle: {
                            normal: {
                                color: '#B94D23'
                            }
                        },
                        data:[0]
                    },
                    {
                        name:'5xx??????',
                        type:'bar',
                        label: {
                            normal: {
                                show: true
                            }
                        },
                        itemStyle: {
                            normal: {
                                color: '#F75903'
                            }
                        },
                        data:[0]
                    },


                ]
            };
	        var chart = echarts.init(document.getElementById('status-area'));
	        chart.setOption(option);
	        _this.data.stateChart = chart;
        },

    };
}(APP));
